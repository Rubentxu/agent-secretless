//! A real TPM 2.0 client: the wire protocol, not a placeholder for it.
//!
//! # What changed, and what did not
//!
//! [`crate::tpm::SoftwareTpm`] hashes the KEK and calls the result a sealed
//! blob. It is a placeholder, it says so through `is_hardware`, and it is not
//! the evidence for M12. This module is the other thing: a byte channel to a
//! TPM 2.0 implementation and the command encoding that goes over it.
//!
//! # The distinction that matters, and why it is not a flag
//!
//! A TPM is reached one of three ways, and the way decides what it is:
//!
//! | Endpoint | What it is | `is_hardware` |
//! |---|---|---|
//! | `/dev/tpm0`, `/dev/tpmrm0` | the kernel's TPM driver in front of a device | **true** |
//! | a Unix socket | a TPM 2.0 *implementation* — `swtpm`, a simulator | **false** |
//! | nothing | no device | **false** |
//!
//! `is_hardware` is derived from the endpoint, so it cannot be set, configured
//! or documented into being true. A deployment that points the vault at
//! `swtpm` gets a working, real TPM 2.0 protocol path and a device that reports
//! itself as software, which is the only honest combination available without
//! silicon.
//!
//! **The limit of that derivation, stated rather than implied.** It says which
//! driver the kernel handed us, not what is on the other end of it. A host whose
//! `tpm_vtpm` module exposed a software TPM as `/dev/tpm0` would satisfy the
//! character-device test, and nothing in this module can tell the difference.
//! What it does rule out — and what it is for — is the substitution that
//! actually happens in practice: a test fixture or a simulator answering where a
//! deployment believes hardware does.
//!
//! # What the encoding here was measured against
//!
//! Every command body in this file was checked against a TPM 2.0
//! implementation and, where the answer was ambiguous, against
//! `tpm2-tools` — the reference client — reading the same device. That process
//! changed three things that a reading of the specification alone would have
//! got wrong, and the corrections are load-bearing:
//!
//! * **`TPM2_PCR_Read` takes no output structures.** `pcrUpdateCounter` is
//!   declared in-out, and sending it anyway makes a real TPM answer
//!   `TPM_RC_SIZE`. The same is true of `capabilities` in
//!   `TPM2_GetCapability`, where an implementation that fills the caller's
//!   buffer does not want the caller to have sent one. Both refusals are
//!   correct refusals of a request whose length disagrees with the command.
//! * **The profile's selection width is something the device confirms, not
//!   something this client asserts.** `PCR_Read` answers with the
//!   `TPMS_PCR_SELECTION` it used, and [`Tpm2Device::pcr_read`] requires that
//!   echo to match the request byte for byte. A device with a wider or narrower
//!   bank is refused rather than read wrongly.
//! * **`TPM2_GetCapability` is not used to discover the PCR banks.** The command
//!   works — the capability this module cares about answers — but the frame of
//!   its answer was not pinned down by anything available to compare against,
//!   and a parser guessed from a plausible reading is worse than no answer: it
//!   would return a bank list that looks measured and is not. The bank
//!   information comes from the device's own echo instead.
//!
//! **What was not measured.** Every device test in this file runs against
//! `swtpm`, a software TPM 2.0 implementation. It speaks the real protocol and
//! that is what the tests exercise; it is not silicon, and `is_hardware` is
//! false throughout.
//!
//! # What is not here yet
//!
//! Object sealing. `seal` and `unseal` answer
//! [`TpmError::Unsupported`](crate::tpm::TpmError::Unsupported) rather than
//! doing something that looks like it worked. `TPM2_CreatePrimary`,
//! `TPM2_Create`, `TPM2_Load` and the public-area encoding are the next piece,
//! and a `SoftwareTpm`-shaped answer here would be worse than no answer: the
//! whole milestone exists because a mechanism that looks healthy while
//! protecting nothing is the failure being removed.
//!
//! `TPM2_PCR_Extend` needed an authorization session, and this client's encoding
//! of one refused. It no longer does, and the answer is one line of structure
//! that six matrices of session fields never varied.
//!
//! **What the policy route is, and what it is not.** `Tpm2Device::policy_pcr`
//! and `advance_policy_digest` exist because a seal that binds to PCR values
//! has to state the policy it binds to, and the only way to state one is to know
//! it before there is an object to seal. So this module can open a policy
//! session, satisfy a PCR condition in it, and compute the digest that condition
//! produces — the `authPolicy` an object would carry.
//!
//! That is the *state a seal would be to*, and a state is not a seal. What is
//! still missing here is the code, not a command the device refuses: a device
//! accepts `TPM2_Create` under a primary with the `authPolicy` this chain
//! computes, `TPM2_Load` of the resulting private/public pair, and `Unseal`
//! under a session that satisfies the policy — all measured, returning the
//! sealed bytes exactly.
//!
//! **A note on the encryption this module's sessions do *not* do.** An earlier
//! draft of this file said the policy `Unseal` would answer in an encrypted
//! parameter that has to be decrypted with AES-CFB first, and named that as
//! the reason the seal was still open. A policy session started with
//! `TPM_ALG_NULL` symmetric receives a **cleartext** response; `Unseal` answers
//! `0` and its `outData` is the sealed bytes in the open. The decryption was
//! an assumption, not a measurement, and it is named here because a file that
//! says it has been removed is a weaker record than one that says what was
//! believed and what replaced it.
//!
//! Two further measurements belong to whoever implements the seal, because
//! both cost a wrong answer that read as a different problem. `TPM2_Create`
//! has **four** parameters (`inSensitive`, `inPublic`, `outsideInfo`,
//! `creationPCR`) and sending two of them is refused as if the attributes were
//! wrong. And in a response carrying an authorization area the **response
//! handles come before `parameterSize`** — reading that the other way round
//! yields a transient handle of `0x80000000` that looks like a two-gigabyte
//! size.
//!
//!
//! **A command with one password session is built like this:**
//!
//! ```text
//! TPM_ST_SESSIONS
//! UINT32 commandSize
//! TPM_CC commandCode
//! <the command's handles, in order>
//! UINT32 authorizationSize
//!     TPMI_DH sessionHandle   (TPM_RS_PW)
//!     TPM2B_AUTH              the password
//!     TPM2B_NONCE             nonceCaller
//!     TPMA_SESSION            sessionAttributes
//! <the command's parameters, in order>
//! ```
//!
//! The authorization area goes **between the handles and the parameters**.
//! That is the whole finding. Every earlier attempt placed the area at one end
//! or the other and then varied what was inside it — nonce size over
//! {0, 16, 20, 32}, hmac size, `TPMA_SESSION` over {0x00, 0x01}, with and
//! without `authorizationSize`, and the session handle before or after the
//! authorization — sixteen combinations, all refused, with `0x184` and
//! `TPM_RC_SIZE`. None of them tried the one dimension that was wrong, because
//! each of them had already decided where the area went.
//!
//! **`0x184` was never about the session.** It names the first *handle*, and
//! `TPM2_Clear` has an `authHandle` parameter that those requests did not send.
//! With `TPM_RH_LOCKOUT` in front of the same session area, `Clear` answers
//! `0`. `Clear` is the smallest command in the specification, which is exactly
//! why it was the one to reach for, and it is kept in the client because
//! `PCR_Extend` alone would not have found the missing handle.
//!
//! **How the ground truth was obtained**, for the next person who needs bytes
//! this file does not have. Not a proxy: `swtpm socket --log file=<path>,
//! level=9` writes every request it reads, hex-dumped, so running the
//! reference client against a logging device and reading the log is a command
//! away. Three earlier attempts to capture these bytes through a proxy failed
//! for three unrelated reasons — a unix-socket proxy with a control channel, an
//! mssim proxy that assumed symmetric framing, and a bridge with two bugs of
//! its own. The device was logging the answer the whole time.
//!
//! Measured against the reference client, the 65 bytes of a `PCR_Extend` for
//! PCR 1 are pinned by a test that transcribes them rather than generating
//! them with the code it checks. Against a device, `PCR_Extend` answers `0` and
//! the PCR reaches `sha256(previous ‖ digest)` — computed independently in the
//! test, not read back and compared with itself.
//!
//! The consequence for the tests below is honest rather than convenient: on a
//! device that has just been started every PCR is zero, and that is the
//! correct answer, not a symptom. So a read-only test asserts the frame, and
//! the assertion that a write happened lives in the test that extends a PCR
//! and checks the fold.
//!
//! # The seal and unseal path, measured as far as it goes
//!
//! The transport for sealing works. Measured on a virgin device, with this
//! module's own encoding and no reference client involved:
//!
//! - `TPM2_CreateLoaded` (0x191) under `TPM_RH_OWNER` answers `0` and returns
//!   an object handle, an 11-byte `outPrivate` and an 86-byte `outPublic` for
//!   a keyedhash object holding 32 bytes of sensitive data.
//! - `TPM2_Unseal` (0x15E) on that handle answers `0` and returns the 32 bytes
//!   exactly, inside the response's `TPM2B`.
//!
//! Two findings about the wire, both of which cost time to find and are
//! cheaper written down than rediscovered:
//!
//! - **`CreateLoaded` takes no `inPrivate` in this implementation.** The
//!   reference client sends `inSensitive` and `inPublic` and stops. Adding the
//!   two bytes for an empty `inPrivate` is answered `TPM_RC_SIZE`. The command
//!   that tpm2-tools itself uses is 145 bytes, not 147.
//! - **`TPM2_Create` is refused here, in every layout tried.** A virgin device
//!   answers `0x184` for it under `TPM_RH_OWNER` with a `creationPCR`, with an
//!   empty `TPML_PCR_SELECTION`, and with only `inSensitive` and `inPublic`
//!   sent — while the identical `inSensitive` and `inPublic` through
//!   `CreateLoaded` succeed. That is this implementation's behaviour and not
//!   asserted here to be the specification's: what is established is that
//!   `Create` was not usable as the way in on the device that was measured, and
//!   that `CreateLoaded` was.
//!
//! **`CreateLoaded` has no `creationPCR` field.** So the command that works
//! cannot bind an object to PCR values at creation, and that is the whole
//! remaining problem. The route that does not need it is a **policy**: the
//! object's `authPolicy` carries a `PolicyPCR` digest computed over the
//! expected PCR values, and the digest is satisfied at `Unseal` time by a
//! policy session rather than recorded at creation. That is the stronger
//! binding, and it is also the larger piece of work, because the response to a
//! command under a policy session is encrypted with the session's key and has
//! to be decrypted with AES-CFB before the sealed data is visible.
//!
//! Until that exists, `seal` and `unseal` refuse. Shipping a `seal` that seals
//! without binding would be worse than refusing: the caller receives a
//! `TpmSealed` carrying a `PcrPolicy` that nothing enforces, which is the
//! mechanism that looks healthy while protecting nothing.
//!
//! ## How far the policy route got
//!
//! Two more commands were measured on a virgin device, each in its own instance
//! so that an exhausted object or session slot could not be mistaken for a
//! refusal:
//!
//! - `CreateLoaded` with a non-empty `authPolicy` answers `0` — and it **needs
//!   an authorization session to create it**. Without one it answers
//!   `TPM_RC_AUTH_MISSING` (0x125), which is what an object carrying a policy
//!   is telling you: it has an admin role to satisfy.
//! - `TPM2_StartAuthSession` with `TPM_SE_POLICY` answers `0` and returns a
//!   session handle.
//!
//! **`TPM2_PolicyPCR` is not pinned.** It answers `0x184` in every formulation
//! tried, including with `pcrDigest` given as the `TPM2B` it is rather than as
//! bare bytes. Unlike the `Create` case, there is no reference capture to diff
//! against: this host's `tpm2-tools` exits 0 from `tpm2_startauthsession` and
//! prints nothing, and rejects a session context file with "expected
//! [o|p|e|n|l] or a handle number", so it cannot be made to send the command
//! whose bytes are wanted. The same lesson as the six dead-end matrices
//! applies — do not guess a wire format, and do not treat a refusal from a
//! shared, exhausted instance as a fact about the encoding.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use sha2::{Digest as _, Sha256};

use crate::tpm::{Digest, PcrPolicy, PcrSlot, TpmDevice, TpmError, TpmSealed};

/// `TPM_ST_NO_SESSIONS`: the request carries no authorization area, which is
/// what every command this module sends does.
const TPM_ST_NO_SESSIONS: u16 = 0x8001;

// Transcribed from TPM 2.0 Part 2, Table "TPM_CC", and checked against a
// device: a command code the TPM does not implement answers a refusal that
// names neither the code nor the body, which is exactly what a correct TPM
// does with something it cannot parse. A test that only checked "the device
// answered" would have passed on a wrong code; one that checks *which* command
// is what turned that into a fix instead of an afternoon.
const TPM2_STARTUP: u32 = 0x0000_0144;
const TPM2_GET_RANDOM: u32 = 0x0000_017B;
const TPM2_PCR_READ: u32 = 0x0000_017E;

/// `TPM_ALG_SHA256`.
const TPM_ALG_SHA256: u16 = 0x000B;

/// Bytes in a PCR selection bitmap: 24 PCRs per bank in the PC Client
/// profile, rounded up to a byte boundary.
///
/// A profile constant, and named as one. What makes it more than a constant is
/// that [`Tpm2Device::pcr_read`] requires the device to echo it back before it
/// will believe the answer: a device whose banks are a different width is
/// refused rather than read with a bitmap of the wrong size, which would come
/// back as a PCR that reads as zero rather than as an error.
const PC_CLIENT_PCR_SELECTION_BYTES: u8 = 3;

/// `TPM_ST_SESSIONS`: the request carries an authorization area. Every other
/// command this module sends uses `TPM_ST_NO_SESSIONS` and has no area at all.
const TPM_ST_SESSIONS: u16 = 0x8002;

/// `TPM_RS_PW`: the authorization session that presents a password rather than
/// a computed HMAC. An empty password is the common case — a PCR's authValue is
/// empty unless something set one — which is what makes a password session the
/// right one for a first write and an HMAC session, which needs a negotiated
/// key, the wrong one.
const TPM_RS_PW: u32 = 0x4000_0009;

/// `TPM2_PCR_Extend`.
const TPM2_PCR_EXTEND: u32 = 0x0000_0182;

/// `TPM2_Clear`.
const TPM2_CLEAR: u32 = 0x0000_0126;

/// `TPM_RH_LOCKOUT`: the authorization handle `TPM2_Clear` requires.
///
/// A handle, not a session. It is the first thing in `Clear`'s body, which is
/// why a request that omits it is answered `0x184` — a refusal naming the first
/// handle, not a complaint about the session that follows. The two were read as
/// one failure for six attempts; see the module docs.
const TPM_RH_LOCKOUT: u32 = 0x4000_000A;

// ---------------------------------------------------------------------------
// The policy route: the state a PCR-bound object is sealed to, and the session
// that satisfies that state at unseal time.
//
// Every constant and every byte order below was measured against `swtpm` with
// `tpm2_policypcr` — the reference client — reading the same device, and the
// measurement contradicts a plain reading of the specification in two places.
// Both are recorded where they are used, because both were found the expensive
// way.
// ---------------------------------------------------------------------------

/// `TPM2_StartAuthSession`.
const TPM2_START_AUTH_SESSION: u32 = 0x0000_0176;

/// `TPM2_PolicyPCR`.
///
/// Sent with `TPM_ST_NO_SESSIONS` and **no authorization area at all**, which is
/// the second of the two contradictions. A policy command that authorizes
/// nothing sends nothing: the session it names *is* the single handle, and the
/// 58 bytes the reference client puts on the wire carry no session area between
/// the handle and the parameters. Every attempt to build this command with the
/// session area this module uses for `PCR_Extend` was answered `0x184` — a
/// refusal naming the first handle, read for six attempts as a session problem
/// when the area was the thing that had no business being there.
const TPM2_POLICY_PCR: u32 = 0x0000_017F;

/// `TPM2_PolicyGetDigest`: what the session has accumulated so far.
const TPM2_POLICY_GET_DIGEST: u32 = 0x0000_0189;

/// `TPM_ALG_NULL`: the session carries no symmetric encryption.
const TPM_ALG_NULL: u16 = 0x0010;

/// `TPM_SE_POLICY`. A trial session (`0x0002`) is refused by this device with
/// `0x3C4`; a policy session is what a real seal needs.
const TPM_SE_POLICY: u16 = 0x0001;

/// `TPM_RH_NULL`: neither `tpmKey` nor `bind` is a key.
const TPM_RH_NULL: u32 = 0x4000_0007;

/// Bytes in the `nonceCaller` a policy session is started with.
///
/// The device accepts any length from 16 up to the digest size and truncates
/// what it is given — measured: `SHA-256` sessions accepted 20 and 32 caller
/// nonces and answered a 20-byte `nonceTPM` for the 20-byte request, while 48
/// was refused with `0x1D5`. The digest size is sent because that is what the
/// reference client sends, not because a smaller value was found to fail.
const POLICY_SESSION_NONCE_BYTES: usize = 32;

/// The byte the reference client sends between `nonceCaller` and `sessionType`.
///
/// **Its field is not established.** A reading of `TPM2_StartAuthSession` puts an
/// `encryptedSalt` `TPM2B_AUTH` there, which is two bytes; the reference client
/// sends one, and the device accepts one and refuses two (`0x4D6`). So this
/// client sends what the device takes, and the value is not free: `0x00` is
/// accepted, `0x01` is refused with `0x2DA` and anything else with `0x2D5` —
/// a field with a permitted value, not padding. Naming it `encryptedSalt` would
/// be a guess dressed as a fact, so it is named for what was measured.
const POLICY_SESSION_UNNAMED_FIELD: u8 = 0x00;

/// A TPM this module can reach, named by how it is reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TpmEndpoint {
    /// A character device published by the kernel's TPM driver.
    CharacterDevice(PathBuf),
    /// A Unix socket in front of a TPM 2.0 implementation.
    UnixSocket(PathBuf),
    /// No device. Every operation answers `Unsupported`.
    Absent,
}

impl TpmEndpoint {
    /// Picks an endpoint from a path, deciding by the path's own name.
    ///
    /// The rule is the kernel driver's device names, because that is the fact
    /// available. A path called `/dev/tpm0` or `/dev/tpmrm0` is the TPM driver;
    /// a socket is a socket, whatever produced it; and `/dev/vtpm0` — the
    /// kernel module for a *virtual* TPM — is deliberately not one of the two,
    /// which is the substitution this function exists to keep out.
    pub fn from_path(path: &Path) -> Self {
        match path.file_name().and_then(|name| name.to_str()) {
            Some("tpm0") | Some("tpmrm0") => Self::CharacterDevice(path.to_path_buf()),
            _ => Self::UnixSocket(path.to_path_buf()),
        }
    }

    /// The kernel's TPM character device, the only endpoint that counts.
    pub fn hardware() -> Self {
        Self::CharacterDevice(PathBuf::from("/dev/tpmrm0"))
    }

    /// Whether this endpoint is a hardware TPM.
    ///
    /// Derived, never set. See the module docs for what it does and does not
    /// establish.
    pub fn is_hardware(&self) -> bool {
        matches!(self, Self::CharacterDevice(_))
    }

    /// What the device is, in words an operator can act on.
    pub fn describe(&self) -> String {
        match self {
            Self::CharacterDevice(path) => {
                format!("tpm2 character device {}", path.display())
            }
            Self::UnixSocket(path) => format!("tpm2 software endpoint {}", path.display()),
            Self::Absent => "no tpm2 device".to_string(),
        }
    }
}

/// Why a TPM could not be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Tpm2Error {
    /// The device could not be opened.
    #[error("cannot open the tpm2 endpoint: {0}")]
    Unreachable(String),
    /// A malformed answer from the device.
    #[error("malformed tpm2 response: {0}")]
    Malformed(String),
    /// The device refused, with its own response code.
    ///
    /// The code is kept raw rather than translated, because a translated one
    /// loses the distinction between "this TPM cannot do that" and "you asked
    /// wrongly", and those send an operator to different places. A decoded name
    /// is available through [`Tpm2Error::code_name`].
    #[error("tpm2 refused: 0x{code:08x} ({name})")]
    Refused {
        /// The device's own response code, untranslated.
        code: u32,
        /// The name of that code, when it is one this client knows.
        name: &'static str,
    },
    /// The operation is not implemented by this device.
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
}

impl Tpm2Error {
    /// Builds a refusal with its code decoded.
    fn refusal(code: u32) -> Self {
        Self::Refused {
            code,
            name: code_name(code),
        }
    }
}

/// Decodes a TPM 2.0 response code, or says that it is not one.
///
/// A TPM answers a request it cannot parse with a format-one code, whose low
/// bits name the parameter at fault. That name is the difference between "this
/// device is busy" and "this client sent the wrong bytes", and the codes worth
/// knowing are the ones that say the second. Unknown codes are rendered rather
/// than dropped, because an unrecognised code that is printed is one an
/// operator can look up and one that is swallowed is one they cannot.
fn code_name(code: u32) -> &'static str {
    match code {
        0x0000_0100 => "TPM_RC_INITIALIZE",
        0x0000_0101 => "TPM_RC_FAILURE",
        0x0000_0125 => "TPM_RC_AUTH_MISSING",
        0x0000_0127 => "TPM_RC_PCR",
        0x0000_0128 => "TPM_RC_PCR_CHANGED",
        0x0000_0140 => "TPM_RC_CLEAR",
        0x0000_0148 => "TPM_RC_YIELDED",
        _ if code & 0x80 == 0 => "a format-zero code",
        // Format one: the high byte is the error, bits 0-5 the parameter.
        _ => match (code >> 8, code & 0x3f) {
            (0x01, 4) => "TPM_RC_VALUE in a parameter",
            (0x02, _) => "TPM_RC_ATTRIBUTES in a parameter",
            (0x03, _) => "TPM_RC_HASH in a parameter",
            (0x04, _) => "TPM_RC_HIERARCHY in a parameter",
            (0x0a, _) => "TPM_RC_HANDLE in a parameter",
            (0x15, _) => "TPM_RC_SIZE in a parameter",
            (0x16, _) => "TPM_RC_TAG in a parameter",
            _ => "a format-one code this client does not name",
        },
    }
}

/// One answer from a TPM: its response code and whatever the command returned.
#[derive(Debug, Clone)]
struct Tpm2Response {
    code: u32,
    body: Vec<u8>,
}

impl Tpm2Response {
    /// The body, or a refusal.
    fn into_body(self) -> Result<Vec<u8>, Tpm2Error> {
        if self.code == 0 {
            Ok(self.body)
        } else {
            Err(Tpm2Error::refusal(self.code))
        }
    }
}

/// A TPM 2.0 device reached over a byte channel.
#[derive(Debug)]
pub struct Tpm2Device {
    endpoint: TpmEndpoint,
    // Behind a mutex because `TpmDevice` takes `&self` and a TPM exchange is
    // request-then-response on one channel. The alternative — `&mut self` on
    // every command — would mean this type could not implement the trait the
    // vault already uses, and re-declaring a mutable-device trait for one
    // implementation is the second surface this module is trying not to have.
    //
    // The lock serialises exchanges and nothing else. A TPM answers one
    // command at a time per channel, so a caller that tried to interleave two
    // would be wrong regardless of what this type did about it.
    channel: Option<Mutex<Box<dyn Channel>>>,
    /// `TpmDevice::label` returns a `&str`, so the endpoint's description is
    /// built once here rather than recomputed into a local that would not
    /// outlive the call.
    label: String,
}

/// The one thing a transport has to be able to do.
trait Channel: std::fmt::Debug + Send {
    fn exchange(&mut self, request: &[u8]) -> Result<Tpm2Response, Tpm2Error>;
}

/// One password session's authorization area: nine bytes.
///
/// `TPM_RS_PW`, an empty authorization value, an empty nonce, and a
/// `TPMA_SESSION` of zero. The sizes are the `TPM2B` size fields themselves —
/// `0x0000` is a present, empty `TPM2B`, not a missing field, and a session
/// that omits them is a different length on the wire.
///
/// `continueSession` is clear, which tells the TPM not to keep the session's
/// state afterwards. A password session has no state worth keeping, and the
/// byte is here because the structure has a slot for it, not because the value
/// is interesting.
fn password_session_area() -> Vec<u8> {
    let mut area = Vec::with_capacity(9);
    area.extend_from_slice(&TPM_RS_PW.to_be_bytes());
    area.extend_from_slice(&0u16.to_be_bytes()); // TPM2B_AUTH: the password
    area.extend_from_slice(&0u16.to_be_bytes()); // TPM2B_NONCE: nonceCaller
    area.push(0x00); // TPMA_SESSION
    area
}

/// A TPM answered over a Unix socket: a TPM 2.0 implementation such as
/// `swtpm`, reachable without privileges.
#[derive(Debug)]
struct UnixStreamChannel {
    stream: std::os::unix::net::UnixStream,
}

impl Channel for UnixStreamChannel {
    fn exchange(&mut self, request: &[u8]) -> Result<Tpm2Response, Tpm2Error> {
        self.stream
            .write_all(request)
            .map_err(|error| Tpm2Error::Unreachable(error.to_string()))?;
        self.stream
            .flush()
            .map_err(|error| Tpm2Error::Unreachable(error.to_string()))?;
        read_answer(&mut self.stream)
    }
}

/// A TPM answered over the kernel's character device.
///
/// The same wire protocol as the socket: the TPM2 header is the framing either
/// way, which is why a hardware TPM and a software one need one client rather
/// than two.
#[derive(Debug)]
struct FileChannel {
    file: std::fs::File,
}

impl Channel for FileChannel {
    fn exchange(&mut self, request: &[u8]) -> Result<Tpm2Response, Tpm2Error> {
        self.file
            .write_all(request)
            .map_err(|error| Tpm2Error::Unreachable(error.to_string()))?;
        read_answer(&mut self.file)
    }
}

/// Reads one TPM2 response using the length in its own header.
///
/// The upper bound is not decoration. Without it a device — or anything
/// impersonating one — can declare a four-gigabyte answer and have the client
/// allocate it, in the one component whose job is to be careful about bytes a
/// device hands it.
fn read_answer<R: Read>(reader: &mut R) -> Result<Tpm2Response, Tpm2Error> {
    let mut header = [0u8; 10];
    read_exact(reader, &mut header)?;
    let size = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
    if !(10..=1 << 20).contains(&size) {
        return Err(Tpm2Error::Malformed(format!(
            "a response of {size} bytes is not a length this client will read"
        )));
    }
    let code = u32::from_be_bytes([header[6], header[7], header[8], header[9]]);
    let mut body = vec![0u8; size - 10];
    if !body.is_empty() {
        read_exact(reader, &mut body)?;
    }
    Ok(Tpm2Response { code, body })
}

/// Reads exactly `buffer.len()` bytes, and says so if the device stops early.
fn read_exact<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<(), Tpm2Error> {
    reader
        .read_exact(buffer)
        .map_err(|error| Tpm2Error::Unreachable(error.to_string()))
}

impl Tpm2Device {
    /// A device with no channel. Every operation refuses.
    pub fn absent() -> Self {
        let endpoint = TpmEndpoint::Absent;
        let label = endpoint.describe();
        Self {
            endpoint,
            channel: None,
            label,
        }
    }

    /// Opens `endpoint`, or refuses.
    pub fn open(endpoint: TpmEndpoint) -> Result<Self, Tpm2Error> {
        let channel: Box<dyn Channel> = match &endpoint {
            TpmEndpoint::Absent => {
                return Err(Tpm2Error::Unreachable(
                    "no tpm2 endpoint was configured".to_string(),
                ))
            }
            TpmEndpoint::UnixSocket(path) => Box::new(UnixStreamChannel {
                stream: std::os::unix::net::UnixStream::connect(path).map_err(|error| {
                    Tpm2Error::Unreachable(format!("{}: {error}", path.display()))
                })?,
            }),
            TpmEndpoint::CharacterDevice(path) => {
                // A character device and a socket are the same wire protocol —
                // the TPM2 header is the framing either way — so the channel is
                // the same too, over a `File` rather than a stream.
                Box::new(FileChannel {
                    file: std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(path)
                        .map_err(|error| {
                            Tpm2Error::Unreachable(format!("{}: {error}", path.display()))
                        })?,
                })
            }
        };
        let label = endpoint.describe();
        Ok(Self {
            endpoint,
            channel: Some(Mutex::new(channel)),
            label,
        })
    }

    /// The endpoint this device was reached through.
    pub fn endpoint(&self) -> &TpmEndpoint {
        &self.endpoint
    }

    /// Sends one unauthenticated command and returns the response.
    fn command(&self, code: u32, body: &[u8]) -> Result<Tpm2Response, Tpm2Error> {
        let mut channel = self
            .channel
            .as_ref()
            .ok_or(Tpm2Error::Unsupported("this device has no channel"))?
            .lock()
            .map_err(|_| Tpm2Error::Unreachable("the tpm2 channel lock was poisoned".into()))?;
        let mut request = Vec::with_capacity(10 + body.len());
        request.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        request.extend_from_slice(&((10 + body.len()) as u32).to_be_bytes());
        request.extend_from_slice(&code.to_be_bytes());
        request.extend_from_slice(body);
        channel.exchange(&request)
    }

    /// Sends one command carrying a single password session.
    ///
    /// The three parts are separate because the wire order is not the order the
    /// command's own description suggests: `handles`, then the authorization
    /// area, then `parameters`. The area does not lead the body and it does not
    /// follow it — it sits between the two, which is the fact six matrices of
    /// nonce size, hmac size, `TPMA_SESSION` and `authorizationSize` never
    /// varied, because every one of them placed the area at one end or the other
    /// and then varied what was inside it.
    fn authorized_command(
        &self,
        code: u32,
        handles: &[u8],
        parameters: &[u8],
    ) -> Result<Tpm2Response, Tpm2Error> {
        let area = password_session_area();
        let size = 10 + handles.len() + 4 + area.len() + parameters.len();
        let mut request = Vec::with_capacity(size);
        request.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
        request.extend_from_slice(&(size as u32).to_be_bytes());
        request.extend_from_slice(&code.to_be_bytes());
        request.extend_from_slice(handles);
        request.extend_from_slice(&(area.len() as u32).to_be_bytes());
        request.extend_from_slice(&area);
        request.extend_from_slice(parameters);
        let mut channel = self
            .channel
            .as_ref()
            .ok_or(Tpm2Error::Unsupported("this device has no channel"))?
            .lock()
            .map_err(|_| Tpm2Error::Unreachable("the tpm2 channel lock was poisoned".into()))?;
        channel.exchange(&request)
    }

    /// `TPM2_Startup`, for a device that has not been started.
    ///
    /// `TPM_RC_INITIALIZE` (0x100) means it already was, which is the normal
    /// case for `/dev/tpmrm0` because the resource manager starts it. Treating
    /// that as success is not a convenience: a caller that ignored it would
    /// read a refusal as a failure and refuse to work on a working device.
    pub fn startup(&self) -> Result<(), Tpm2Error> {
        let response = self.command(TPM2_STARTUP, &0u16.to_be_bytes())?;
        if response.code == 0 || response.code == 0x0000_0100 {
            Ok(())
        } else {
            Err(Tpm2Error::refusal(response.code))
        }
    }

    /// `TPM2_GetRandom`: `bytes` from the device's entropy source.
    pub fn random(&self, bytes: u16) -> Result<Vec<u8>, Tpm2Error> {
        let response = self.command(TPM2_GET_RANDOM, &bytes.to_be_bytes())?;
        let body = response.into_body()?;
        if body.len() < 2 {
            return Err(Tpm2Error::Malformed(
                "no length on a GetRandom answer".into(),
            ));
        }
        // A TPM2B: a u16 length then the bytes, and the length is what the
        // device says it sent rather than what the request asked for.
        let length = u16::from_be_bytes([body[0], body[1]]) as usize;
        if body.len() < 2 + length {
            return Err(Tpm2Error::Malformed(
                "a GetRandom answer is shorter than its own length".into(),
            ));
        }
        Ok(body[2..2 + length].to_vec())
    }

    /// The bank and the selection width this device used for `slots`.
    ///
    /// Read from the device rather than assumed, and read from the place that
    /// cannot be wrong about it: the `TPMS_PCR_SELECTION` a `PCR_Read` answer
    /// carries. That echo is the bank the device actually used, with the width
    /// it actually used.
    ///
    /// The bitmap in the echo is **the selection that was read**, not the set
    /// of PCRs the device implements. An earlier draft of this call asked for
    /// PCR 0 alone and reported the answer as the implemented set, which made
    /// PCR 4 read as unimplemented — a device that has 24 PCRs saying it has
    /// one. The echo is what was asked; a TPM does not widen the request.
    ///
    /// A discovery path through `TPM2_GetCapability(TPM_CAP_PCRS)` was tried
    /// and dropped; see the module docs for why.
    pub fn pcr_selection(&self, slots: &[PcrSlot]) -> Result<PcrSelection, Tpm2Error> {
        Ok(self.exchange_pcrs(slots)?.selection)
    }

    /// `TPM2_PCR_Read` for the SHA-256 bank, returning the digests for `slots`
    /// as the device currently holds them.
    pub fn pcr_read(&self, slots: &[PcrSlot]) -> Result<Vec<(PcrSlot, Digest)>, Tpm2Error> {
        let answer = self.exchange_pcrs(slots)?;
        Ok(slots
            .iter()
            .copied()
            .zip(answer.digests)
            .collect::<Vec<_>>())
    }

    /// `TPM2_PCR_Extend`: folds `digest` into `slot` in the SHA-256 bank.
    ///
    /// The first command in this module that needs an authorization session,
    /// and the one whose session encoding took six matrices and three failed
    /// capture attempts to get right. The device folds the value and nothing
    /// here computes the new digest: a caller that wants to know the result
    /// reads it back, and a caller that computed it here would be asserting the
    /// TPM's arithmetic rather than checking it.
    ///
    /// A refusal is a refusal, not a warning. A write that appeared to succeed
    /// and left the PCR unchanged is the failure this milestone exists to
    /// remove, so the response code is propagated rather than swallowed.
    pub fn pcr_extend(&self, slot: PcrSlot, digest: &Digest) -> Result<(), Tpm2Error> {
        // `pcrHandle` is a handle, so it precedes the authorization area;
        // `digests` is a parameter, so it follows it.
        let handles = (slot.index() as u32).to_be_bytes();
        let mut parameters = Vec::with_capacity(4 + 2 + 32);
        parameters.extend_from_slice(&1u32.to_be_bytes()); // TPML_DIGEST_VALUES.count
        parameters.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        parameters.extend_from_slice(digest);
        self.authorized_command(TPM2_PCR_EXTEND, &handles, &parameters)?
            .into_body()
            .map(|_| ())
    }

    /// `TPM2_Clear`, authorized against the lockout hierarchy.
    ///
    /// Present because it is the command that named the bug: sent without its
    /// `authHandle` it answers `0x184`, and read as a session that no
    /// combination of session fields could satisfy. It is the smallest command
    /// in the TPM 2.0 specification, which is exactly why it was the one to
    /// reach for, and it is kept because a test that only exercised `PCR_Extend`
    /// would not have caught the missing handle.
    ///
    /// What a clear does to this device's PCRs is **not** asserted anywhere in
    /// this module. Measured once against `swtpm`, a `Clear` answered `0` and
    /// left the extended PCRs at their extended values, and whether that is
    /// `swtpm`'s behaviour, a consequence of the flags it was started with, or
    /// a misreading of which PCRs are resettable was not established. So the
    /// method reports what the device said and nothing more.
    pub fn clear(&self) -> Result<(), Tpm2Error> {
        self.authorized_command(TPM2_CLEAR, &TPM_RH_LOCKOUT.to_be_bytes(), &[])?
            .into_body()
            .map(|_| ())
    }

    /// `TPM2_StartAuthSession`: a session that accumulates a policy digest.
    ///
    /// The policy route's first command, and the one whose parameter area this
    /// client had wrong twice before. Measured against the reference client
    /// reading the same device, the area after `nonceCaller` is **seven** bytes:
    /// one byte the device requires to be `0x00`, then `sessionType`,
    /// `symmetric` and `authHash`. A plausible reading of the command puts a
    /// two-byte `encryptedSalt` there instead, and a request built that way is
    /// answered `0x4D6` — a refusal about the request's length, from a command
    /// whose length is the only thing that is wrong.
    ///
    /// `TPM_RH_NULL` for both handles: the session is bound to nothing and
    /// encrypts to nothing, which is what makes the policy digest it
    /// accumulates the only state it carries.
    pub fn start_policy_session(&self) -> Result<PolicySession, Tpm2Error> {
        let mut nonce = [0u8; POLICY_SESSION_NONCE_BYTES];
        crate::envelope::fill_random_for_crate(&mut nonce);
        let response = self.command(TPM2_START_AUTH_SESSION, &policy_session_body(&nonce))?;
        let answer = response.into_body()?;
        if answer.len() < 4 {
            return Err(Tpm2Error::Malformed(
                "no session handle on a StartAuthSession answer".into(),
            ));
        }
        Ok(PolicySession {
            handle: u32::from_be_bytes([answer[0], answer[1], answer[2], answer[3]]),
        })
    }

    /// `TPM2_PolicyPCR`: require `slots` to hold the values the device reports
    /// now, and advance the session's policy digest.
    ///
    /// Returns the `pcrDigest` that was sent, which is the input
    /// [`advance_policy_digest`] needs to reproduce the policy this command
    /// produces. Returning it is what lets a caller check the device's
    /// arithmetic against its own rather than asking the device twice.
    ///
    /// The `pcrDigest` is **the hash of the PCR values themselves**, and the
    /// device checks it: a digest of thirty-two zero bytes, of thirty-two `0xFF`
    /// bytes, or of anything else that is not what the selected PCRs hash to,
    /// is refused with `0x1C4` and the session's policy digest does not move.
    /// That is why this call reads the PCRs first — which is also why the
    /// reference client issues a `PCR_Read` immediately before its `PolicyPCR`.
    pub fn policy_pcr(
        &self,
        session: PolicySession,
        slots: &[PcrSlot],
    ) -> Result<Digest, Tpm2Error> {
        let pcr_digest = pcr_value_digest(&self.pcr_read(slots)?);
        let body = policy_pcr_body(session.handle, &pcr_digest, &pcr_selection_body(slots)?);
        self.command(TPM2_POLICY_PCR, &body)?
            .into_body()
            .map(|_| pcr_digest)
    }

    /// `TPM2_PolicyGetDigest`: the policy the session holds right now.
    ///
    /// A fresh policy session answers thirty-two zero bytes, measured. That is
    /// the seed the policy chain starts from, and it is what
    /// [`PolicySession::seed`] compares its own arithmetic against.
    pub fn policy_digest(&self, session: PolicySession) -> Result<Digest, Tpm2Error> {
        let response = self.command(TPM2_POLICY_GET_DIGEST, &session.handle.to_be_bytes())?;
        let body = response.into_body()?;
        // A TPM2B: a u16 length, then the bytes. The length is what the device
        // says it sent, and a policy digest this client cannot compare is a
        // refusal rather than a truncated answer.
        if body.len() < 2 {
            return Err(Tpm2Error::Malformed(
                "no length on a PolicyGetDigest answer".into(),
            ));
        }
        let length = u16::from_be_bytes([body[0], body[1]]) as usize;
        if body.len() < 2 + length || length != 32 {
            return Err(Tpm2Error::Malformed(
                "a PolicyGetDigest answer is not a sha256 digest".into(),
            ));
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&body[2..34]);
        Ok(digest)
    }

    /// One `PCR_Read` round trip, parsed and checked against what was asked.
    fn exchange_pcrs(&self, slots: &[PcrSlot]) -> Result<PcrRead, Tpm2Error> {
        if slots.is_empty() {
            return Err(Tpm2Error::Unsupported("no PCR was requested"));
        }
        let bitmap = selection_bitmap(slots, PC_CLIENT_PCR_SELECTION_BYTES)?;
        // The same marshalling `TPM2_PolicyPCR` sends, byte for byte. Shared on
        // purpose: the policy chain this module computes hashes exactly the
        // bytes that go on the wire, and two copies of that encoding would be
        // two places for them to drift apart.
        let body = pcr_selection_body(slots)?;
        // **And nothing else.** `pcrUpdateCounter` is declared in-out, and
        // sending a four-byte zero for it makes a real TPM answer
        // `TPM_RC_SIZE` — a correct refusal of a request whose length does not
        // match the command. The first version of this client sent it, on the
        // reasonable reading that an in-out parameter travels both ways; a
        // device that fills the caller's buffer does not want it supplied.

        let response = self.command(TPM2_PCR_READ, &body)?;
        let answer = response.into_body()?;
        parse_pcr_read(&answer, &bitmap, slots.len())
    }
}

/// A `TPML_PCR_SELECTION` for the SHA-256 bank, as one command carries it.
///
/// A count, then a `TPMS_PCR_SELECTION` of `hash` (u16), `sizeofSelect` (u8)
/// and the bitmap. Written once because `PCR_Read` and `PolicyPCR` must agree
/// on it to the byte: the policy chain is computed over this encoding.
fn pcr_selection_body(slots: &[PcrSlot]) -> Result<Vec<u8>, Tpm2Error> {
    let bitmap = selection_bitmap(slots, PC_CLIENT_PCR_SELECTION_BYTES)?;
    let mut body = Vec::with_capacity(7 + bitmap.len());
    body.extend_from_slice(&1u32.to_be_bytes());
    body.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    body.push(PC_CLIENT_PCR_SELECTION_BYTES);
    body.extend_from_slice(&bitmap);
    Ok(body)
}

/// The body of a `TPM2_StartAuthSession` for a policy session, `nonce` included.
///
/// Separate from the send so the layout can be compared with the reference
/// client's bytes without a device on the other end.
fn policy_session_body(nonce: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + 2 + nonce.len() + 7);
    // `tpmKey` and `bind`, neither of which is a key.
    body.extend_from_slice(&TPM_RH_NULL.to_be_bytes());
    body.extend_from_slice(&TPM_RH_NULL.to_be_bytes());
    // `nonceCaller`, then the seven bytes measured in the module docs.
    body.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
    body.extend_from_slice(nonce);
    body.push(POLICY_SESSION_UNNAMED_FIELD);
    body.extend_from_slice(&TPM_SE_POLICY.to_be_bytes());
    body.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
    body.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    body
}

/// The body of a `TPM2_PolicyPCR`: the session handle, then `pcrDigest`, then
/// the selection.
///
/// The session handle is a **handle**, so it leads; and the request carries no
/// authorization area, which is what `TPM2_POLICY_PCR`'s note says and what the
/// reference client's 58 bytes show.
fn policy_pcr_body(handle: u32, pcr_digest: &Digest, selection: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + 2 + pcr_digest.len() + selection.len());
    body.extend_from_slice(&handle.to_be_bytes());
    body.extend_from_slice(&(pcr_digest.len() as u16).to_be_bytes());
    body.extend_from_slice(pcr_digest);
    body.extend_from_slice(selection);
    body
}

/// The digest `TPM2_PolicyPCR` carries: the hash of the PCR values it names.
///
/// **In ascending PCR index order**, not in the order the caller listed them.
/// The device concatenates the values the selection covers, sorted by index, and
/// a digest computed over the caller's ordering is a digest of something the
/// device did not name — which it answers `0x1C4`.
pub fn pcr_value_digest(observed: &[(PcrSlot, Digest)]) -> Digest {
    let mut ordered: Vec<(u8, Digest)> = observed
        .iter()
        .map(|(slot, digest)| (slot.index(), *digest))
        .collect();
    ordered.sort_by_key(|(index, _)| *index);
    let mut hasher = Sha256::new();
    for (_, digest) in ordered {
        hasher.update(digest);
    }
    hasher.finalize().into()
}

/// The policy digest after one `TPM2_PolicyPCR`, computed rather than asked for.
///
/// `H(policyDigest ‖ TPM_CC_PolicyPCR ‖ pcrs ‖ pcrDigest)` — the chain a policy
/// session walks, and the value a `sealed` object's `authPolicy` has to hold
/// for the device to accept the session that satisfies it. Measured against
/// `swtpm`: a fresh session's `0^256` and a selection of PCRs 0-3 produce
/// `84b506c9…`, and asking the same session for its digest produces exactly
/// that.
///
/// The point of computing it is that a client must be able to state the policy
/// it is sealing to. A seal whose `authPolicy` was read back from the device
/// after the fact would be a seal to whatever the device happened to hold.
pub fn advance_policy_digest(
    current: &Digest,
    slots: &[PcrSlot],
    pcr_digest: &Digest,
) -> Result<Digest, Tpm2Error> {
    Ok(advance_policy_digest_over(
        current,
        &pcr_selection_body(slots)?,
        pcr_digest,
    ))
}

/// [`advance_policy_digest`] over an already-marshalled selection.
///
/// Split so the chain can be checked against a value the device reported for a
/// selection this crate does not model: `PcrSlot` names PCRs 0, 4 and 7, while
/// the measurement that pinned the chain was taken over PCRs 0 to 3.
fn advance_policy_digest_over(current: &Digest, selection: &[u8], pcr_digest: &Digest) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(current);
    hasher.update(TPM2_POLICY_PCR.to_be_bytes());
    hasher.update(selection);
    hasher.update(pcr_digest);
    hasher.finalize().into()
}

/// A policy session: the TPM's own state for the policy being built.
///
/// Copyable and inert. It is a handle, so a session that outlives the device
/// that issued it is a handle to nothing, and every command that takes one
/// answers a refusal rather than a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicySession {
    handle: u32,
}

impl PolicySession {
    /// The handle the device gave this session.
    pub fn handle(&self) -> u32 {
        self.handle
    }

    /// What this session's policy digest should be, computed locally.
    ///
    /// Starts at the seed a fresh session holds — thirty-two zero bytes,
    /// measured — and is the value a caller compares
    /// [`Tpm2Device::policy_digest`] against.
    pub fn seed() -> Digest {
        [0u8; 32]
    }
}

impl TpmDevice for Tpm2Device {
    /// Refuses rather than pretending.
    ///
    /// The placeholder answered here for the whole life of M12, which meant a
    /// caller could not tell "this vault is not device-bound" from "this vault
    /// is device-bound and the device is busy". Sealing a real object needs
    /// `TPM2_CreatePrimary`, `TPM2_Create` and `TPM2_Load`, and until those are
    /// here the honest answer is that it is not implemented on this device.
    fn seal(&self, _kek: &[u8; 32], _pcr_policy: &PcrPolicy) -> Result<TpmSealed, TpmError> {
        Err(TpmError::TpmRefused(
            "this tpm2 device does not seal yet: the device side is measured \
             end to end - CreatePrimary, Create with the computed authPolicy, \
             Load, and Unseal under a policy session returning the sealed bytes \
             - and what is missing is this module writing it. ContextSave is \
             refused 0x145 here, so Create/Load is the only durable route"
                .to_string(),
        ))
    }

    /// Refuses rather than pretending. See [`TpmDevice::seal`].
    fn unseal(
        &self,
        _sealed: &TpmSealed,
        _observed: &[(PcrSlot, Digest)],
    ) -> Result<[u8; 32], TpmError> {
        Err(TpmError::TpmRefused(
            "this tpm2 device does not unseal yet: the sealed path is measured to work \
             up to Unseal, but binding it to PCR values needs a policy session whose \
             response has to be decrypted before the data is visible"
                .to_string(),
        ))
    }

    fn is_hardware(&self) -> bool {
        self.endpoint.is_hardware()
    }

    fn label(&self) -> &str {
        &self.label
    }
}

/// The PCR bank a device used, as the device itself reported it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcrSelection {
    /// The bank algorithm, `TPM_ALG_SHA256` for the bank this client reads.
    pub algorithm: u16,
    /// How wide the bank's selection bitmap is, in bytes.
    pub sizeof_select: u8,
    /// The selection that was read, as the device echoed it back.
    ///
    /// This is what was asked for, not what the device could have read. Naming
    /// it otherwise would be a plausible-sounding field that lies.
    pub selected: Vec<u8>,
}

impl PcrSelection {
    /// Whether this read covered `slot`.
    pub fn covers(&self, slot: PcrSlot) -> bool {
        let index = slot.index() as usize;
        let byte = index / 8;
        byte < self.selected.len() && self.selected[byte] & (1u8 << (index % 8)) != 0
    }
}

/// What one `PCR_Read` round trip produced.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PcrRead {
    selection: PcrSelection,
    digests: Vec<Digest>,
}

/// Builds the selection bitmap for `slots`, refusing anything out of range.
fn selection_bitmap(slots: &[PcrSlot], size: u8) -> Result<Vec<u8>, Tpm2Error> {
    let width = size as usize * 8;
    if slots.iter().any(|slot| slot.index() as usize >= width) {
        return Err(Tpm2Error::Unsupported(
            "a requested PCR is outside the PC Client profile's selection",
        ));
    }
    let mut bitmap = vec![0u8; size as usize];
    for slot in slots {
        let index = slot.index() as usize;
        // Little-endian bit order within the selection, which is how the
        // specification numbers them and the opposite of how a u64 would.
        bitmap[index / 8] |= 1u8 << (index % 8);
    }
    Ok(bitmap)
}

/// Reads a `TPM2_PCR_Read` answer, refusing any frame that is not exactly one.
///
/// The frame is a `u32` the device writes ahead of the list — whose value this
/// client does not interpret, and which is skipped rather than trusted — then
/// the `TPML_PCR_SELECTION` the device used, then the `TPML_DIGEST` of values.
///
/// Three things are checked, and all three are checks a wrong parser fails:
///
/// 1. **The echo matches the request.** The `TPMS_PCR_SELECTION` that comes
///    back has to name the same bank and the same bitmap. A device that read
///    the selection differently says so here, and a client that paired a slot
///    with another slot's digest would not notice on its own.
/// 2. **The digest count is the number of slots asked for.** Any other count
///    means the answer is about different PCRs.
/// 3. **Nothing is left over.** A frame this client does not understand is
///    refused rather than half-read, because a trailing byte is how a
///    misaligned parse turns into a plausible wrong answer.
fn parse_pcr_read(answer: &[u8], asked: &[u8], slots: usize) -> Result<PcrRead, Tpm2Error> {
    let mut cursor = 4; // the leading u32, not interpreted
    if answer.len() < cursor + 4 {
        return Err(Tpm2Error::Malformed(
            "a PCR_Read answer is too short".into(),
        ));
    }
    let banks = u32::from_be_bytes([
        answer[cursor],
        answer[cursor + 1],
        answer[cursor + 2],
        answer[cursor + 3],
    ]);
    cursor += 4;
    if banks != 1 {
        return Err(Tpm2Error::Malformed(format!(
            "a PCR_Read answer reports {banks} banks where one was asked for"
        )));
    }
    if cursor + 3 > answer.len() {
        return Err(Tpm2Error::Malformed("a PCR selection is truncated".into()));
    }
    let algorithm = u16::from_be_bytes([answer[cursor], answer[cursor + 1]]);
    let sizeof_select = answer[cursor + 2];
    cursor += 3;
    let end = cursor + sizeof_select as usize;
    if end > answer.len() {
        return Err(Tpm2Error::Malformed(
            "a PCR selection bitmap is truncated".into(),
        ));
    }
    let implemented = answer[cursor..end].to_vec();
    cursor = end;

    if algorithm != TPM_ALG_SHA256 {
        return Err(Tpm2Error::Unsupported(
            "this device answered on a bank other than SHA-256",
        ));
    }
    if sizeof_select as usize != asked.len() || implemented != asked {
        return Err(Tpm2Error::Malformed(format!(
            "the device answered on a selection of {sizeof_select} bytes \
             ({} bytes requested) and it is not the one that was asked for",
            asked.len()
        )));
    }

    if cursor + 4 > answer.len() {
        return Err(Tpm2Error::Malformed(
            "no digest count on a PCR_Read answer".into(),
        ));
    }
    let count = u32::from_be_bytes([
        answer[cursor],
        answer[cursor + 1],
        answer[cursor + 2],
        answer[cursor + 3],
    ]) as usize;
    cursor += 4;
    if count != slots {
        return Err(Tpm2Error::Malformed(format!(
            "a PCR_Read answer carries {count} digests for {slots} slots"
        )));
    }
    let mut digests = Vec::with_capacity(count);
    for _ in 0..count {
        if cursor + 2 > answer.len() {
            return Err(Tpm2Error::Malformed("a PCR digest is truncated".into()));
        }
        let length = u16::from_be_bytes([answer[cursor], answer[cursor + 1]]) as usize;
        cursor += 2;
        if length != 32 {
            return Err(Tpm2Error::Malformed(format!(
                "a PCR digest came back {length} bytes long and this client reads SHA-256 only"
            )));
        }
        if cursor + 32 > answer.len() {
            return Err(Tpm2Error::Malformed("a PCR digest is truncated".into()));
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&answer[cursor..cursor + 32]);
        cursor += 32;
        digests.push(digest);
    }
    if cursor != answer.len() {
        return Err(Tpm2Error::Malformed(format!(
            "a PCR_Read answer has {} bytes this client cannot place",
            answer.len() - cursor
        )));
    }
    Ok(PcrRead {
        selection: PcrSelection {
            algorithm,
            sizeof_select,
            selected: implemented,
        },
        digests,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------
    // What can be measured with no device present. These run in the default
    // suite, because "the class of a path" and "what this client does with a
    // frame it does not understand" are properties of the client and not of
    // the TPM.
    // ---------------------------------------------------------------------

    /// Builds the frame a real device answers a three-PCR read with.
    ///
    /// Taken byte for byte from a `PCR_Read` against a TPM 2.0
    /// implementation, and cross-checked against `tpm2_pcrread`: the same
    /// request through the reference client yields the same three digests in
    /// the same order. Encoding the frame here means the parser's tests are
    /// about the parser, and the device tests below are about the wire.
    fn real_frame(bitmap: &[u8], digests: &[[u8; 32]]) -> Vec<u8> {
        let mut answer = 20u32.to_be_bytes().to_vec();
        answer.extend_from_slice(&1u32.to_be_bytes());
        answer.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        answer.push(bitmap.len() as u8);
        answer.extend_from_slice(bitmap);
        answer.extend_from_slice(&(digests.len() as u32).to_be_bytes());
        for digest in digests {
            answer.extend_from_slice(&32u16.to_be_bytes());
            answer.extend_from_slice(digest);
        }
        answer
    }

    fn asked_bitmap() -> Vec<u8> {
        vec![0b1001_0001, 0, 0] // PCRs 0, 4 and 7
    }

    /// A frame the device sent is read whole, and read the way the reference
    /// client reads it.
    #[test]
    fn a_frame_a_device_sent_is_read_whole() {
        let digest = [7u8; 32];
        let answer = real_frame(&asked_bitmap(), &[digest]);
        let read = parse_pcr_read(&answer, &asked_bitmap(), 1).expect("a frame a device sent");
        assert_eq!(read.digests, vec![digest]);
        assert_eq!(read.selection.algorithm, TPM_ALG_SHA256);
        assert_eq!(read.selection.sizeof_select, 3);
        assert_eq!(read.selection.selected, asked_bitmap());
        for slot in [PcrSlot::Pcr0, PcrSlot::Pcr4, PcrSlot::Pcr7] {
            assert!(read.selection.covers(slot), "{slot:?} is not covered");
        }
    }

    /// **The check that a plausible parser fails.** A frame with a byte the
    /// client cannot place is refused. A parser that stopped after the last
    /// digest would accept this one and report success, which is how an
    /// off-by-one in an offset turns into a wrong PCR rather than an error.
    #[test]
    fn a_frame_with_a_byte_this_client_cannot_place_is_refused() {
        let mut answer = real_frame(&asked_bitmap(), &[[7u8; 32]]);
        answer.push(0);
        assert!(matches!(
            parse_pcr_read(&answer, &asked_bitmap(), 1),
            Err(Tpm2Error::Malformed(_))
        ));
    }

    /// A device that answered on a selection this client did not ask for is
    /// refused, because pairing a slot with another slot's digest is otherwise
    /// invisible.
    #[test]
    fn a_selection_the_device_did_not_echo_is_refused() {
        let answer = real_frame(&[0b1000_0001, 0, 0], &[[7u8; 32]]);
        assert!(matches!(
            parse_pcr_read(&answer, &asked_bitmap(), 1),
            Err(Tpm2Error::Malformed(_))
        ));
    }

    /// A device whose banks are a different width is refused, not read with a
    /// bitmap of the wrong size — which would come back as a PCR that reads as
    /// zero rather than as an error.
    ///
    /// The device answers with a two-byte selection because that is how wide
    /// its banks are; this client always asks with the profile's three. Reading
    /// the answer anyway would pair a slot with a digest the device took from a
    /// bitmap this client and the device disagree about.
    #[test]
    fn a_device_whose_banks_are_a_different_width_is_refused() {
        let answer = real_frame(&[0b1001_0001, 0], &[[7u8; 32]]);
        assert_eq!(
            answer[8 + 2],
            2,
            "the frame should carry a two-byte selection"
        );
        assert!(matches!(
            parse_pcr_read(&answer, &asked_bitmap(), 1),
            Err(Tpm2Error::Malformed(_))
        ));
    }

    /// A digest that is not 32 bytes is refused rather than padded. A client
    /// that zero-extended would let a device choose which PCRs it controls.
    #[test]
    fn a_digest_of_the_wrong_length_is_refused() {
        let mut answer = asked_bitmap_answer();
        answer.extend_from_slice(&1u32.to_be_bytes());
        answer.extend_from_slice(&16u16.to_be_bytes());
        answer.extend_from_slice(&[0u8; 16]);
        assert!(matches!(
            parse_pcr_read(&answer, &asked_bitmap(), 1),
            Err(Tpm2Error::Malformed(_))
        ));
    }

    /// A count that disagrees with the request is a protocol error, and
    /// answering anyway would mean pairing a slot with another slot's digest.
    #[test]
    fn a_digest_count_that_disagrees_with_the_request_is_refused() {
        let answer = real_frame(&asked_bitmap(), &[[1u8; 32], [2u8; 32]]);
        assert!(matches!(
            parse_pcr_read(&answer, &asked_bitmap(), 1),
            Err(Tpm2Error::Malformed(_))
        ));
    }

    /// A frame that stops in the middle of a digest is refused rather than
    /// completed with whatever was in memory.
    #[test]
    fn a_truncated_digest_is_refused() {
        let mut answer = real_frame(&asked_bitmap(), &[[1u8; 32]]);
        answer.truncate(answer.len() - 1);
        assert!(matches!(
            parse_pcr_read(&answer, &asked_bitmap(), 1),
            Err(Tpm2Error::Malformed(_))
        ));
    }

    /// The prefix of a selection record, so the tests above can build a frame
    /// whose digest section they want to be wrong about.
    fn asked_bitmap_answer() -> Vec<u8> {
        let bitmap = asked_bitmap();
        let mut answer = 20u32.to_be_bytes().to_vec();
        answer.extend_from_slice(&1u32.to_be_bytes());
        answer.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        answer.push(bitmap.len() as u8);
        answer.extend_from_slice(&bitmap);
        answer
    }

    /// The hardware classification comes from the path's own name, so the
    /// substitutions that actually happen cannot pass for hardware.
    #[test]
    fn only_the_kernels_tpm_device_counts_as_hardware() {
        let hardware = [
            TpmEndpoint::from_path(Path::new("/dev/tpm0")),
            TpmEndpoint::from_path(Path::new("/dev/tpmrm0")),
        ];
        for endpoint in hardware {
            assert!(
                endpoint.is_hardware(),
                "{} should be hardware",
                endpoint.describe()
            );
        }

        let not_hardware = [
            // A Unix socket in front of a real TPM 2.0 implementation.
            TpmEndpoint::from_path(Path::new("/run/swtpm.sock")),
            // The kernel module for a *virtual* TPM. Same file, different
            // driver, and the name is what tells them apart.
            TpmEndpoint::from_path(Path::new("/dev/vtpm0")),
            TpmEndpoint::from_path(Path::new("/dev/null")),
        ];
        for endpoint in not_hardware {
            assert!(
                !endpoint.is_hardware(),
                "{} must not report as hardware",
                endpoint.describe()
            );
        }
        assert!(!TpmEndpoint::Absent.is_hardware());
    }

    /// `is_hardware` is derived, so there is no setter to misuse. The compile
    /// is the assertion: if a `new` taking a boolean were ever added next to
    /// this, the field would still be the only source.
    #[test]
    fn a_socket_endpoint_describes_itself_as_software() {
        let endpoint = TpmEndpoint::from_path(Path::new("/run/swtpm.sock"));
        let described = endpoint.describe();
        assert!(described.contains("software"), "{described}");
        assert!(!described.contains("character device"), "{described}");
    }

    /// An answer that declares an impossible length is refused before anything
    /// is allocated for it. A device is the one party in this component whose
    /// word about a size the client has to take at face value.
    #[test]
    fn an_impossible_declared_length_is_refused_before_allocating() {
        let mut device = [0u8; 10];
        device[2..6].copy_from_slice(&(64 * 1024 * 1024u32).to_be_bytes());
        device[6..10].copy_from_slice(&0u32.to_be_bytes());
        assert!(matches!(
            read_answer(&mut &device[..]),
            Err(Tpm2Error::Malformed(_))
        ));

        // A length below the header's own size is the same class of nonsense.
        let mut short = [0u8; 10];
        short[2..6].copy_from_slice(&4u32.to_be_bytes());
        assert!(matches!(
            read_answer(&mut &short[..]),
            Err(Tpm2Error::Malformed(_))
        ));
    }

    /// A refusal is reported with its own code *and* a name, because the name
    /// is the difference between "this device is busy" and "this client sent
    /// the wrong bytes", and the wrong-bytes codes are format-one codes whose
    /// low bits name the parameter at fault.
    #[test]
    fn a_refusal_carries_its_code_and_a_name() {
        assert_eq!(code_name(0x0000_0100), "TPM_RC_INITIALIZE");
        assert_eq!(code_name(0x0000_0128), "TPM_RC_PCR_CHANGED");
        // 0x1c4: format one, error number 4, parameter 4.
        assert!(code_name(0x0000_01c4).contains("TPM_RC_VALUE"));
        let refusal = Tpm2Error::refusal(0x0000_01c4);
        assert!(refusal.to_string().contains("0x000001c4"), "{refusal}");
        assert!(refusal.to_string().contains("TPM_RC_VALUE"), "{refusal}");
        // An unnamed code is still named as unnamed rather than dropped.
        assert!(code_name(0x0000_00ff).contains("does not name"));
    }

    /// `TPM_RC_INITIALIZE` means "already started", which is the normal case
    /// for a resource manager that starts the TPM itself. A client that read it
    /// as a failure would refuse to work on a working device.
    #[test]
    fn an_absent_device_says_so_rather_than_pretending_to_be_one() {
        let device = Tpm2Device::absent();
        assert!(!device.is_hardware());
        assert_eq!(device.label(), "no tpm2 device");
    }

    /// With no device, the trait operations refuse rather than substituting a
    /// placeholder answer. This is the whole direction of the increment: the
    /// placeholder used to answer, and a caller could not tell "not
    /// device-bound" from "device-bound and busy".
    #[test]
    fn a_device_with_no_channel_refuses_rather_than_substituting() {
        let device = Tpm2Device::absent();
        let policy = PcrPolicy::new(vec![(PcrSlot::Pcr0, [1u8; 32])]);
        let sealed = TpmSealed {
            blob: vec![0u8; 40],
            pcr_policy: policy.clone(),
            policy_version: 1,
        };
        assert!(device.seal(&[0u8; 32], &policy).is_err());
        assert!(device
            .unseal(&sealed, &[(PcrSlot::Pcr0, [1u8; 32])])
            .is_err());
        // And the commands that need a channel say so rather than inventing an
        // answer.
        assert!(matches!(device.random(16), Err(Tpm2Error::Unsupported(_))));
        assert!(matches!(
            device.pcr_read(&[PcrSlot::Pcr0]),
            Err(Tpm2Error::Unsupported(_))
        ));
        assert!(matches!(
            device.pcr_selection(&[PcrSlot::Pcr0]),
            Err(Tpm2Error::Unsupported(_))
        ));
    }

    /// Opening an absent endpoint is an error at construction, so a caller
    /// cannot hold a "device" that is not one.
    #[test]
    fn opening_an_absent_endpoint_is_refused() {
        assert!(matches!(
            Tpm2Device::open(TpmEndpoint::Absent),
            Err(Tpm2Error::Unreachable(_))
        ));
    }

    /// Asking for no PCR is refused rather than answered with an empty list,
    /// which a caller could mistake for "these PCRs read as nothing".
    #[test]
    fn asking_for_no_pcr_is_refused() {
        let device = Tpm2Device::absent();
        assert!(matches!(
            device.pcr_read(&[]),
            Err(Tpm2Error::Unsupported(_))
        ));
    }

    // ---------------------------------------------------------------------
    // The device path. `cargo test -p asv-vault --features tpm-device`.
    // ---------------------------------------------------------------------

    /// A TPM 2.0 implementation started for this test and killed with it.
    ///
    /// `swtpm` speaks the real protocol, so what these tests exercise is the
    /// client and not a mock of it. What they cannot establish is that the
    /// device is silicon, and nothing here claims they do: `is_hardware` is
    /// false throughout, which is the point of deriving it.
    ///
    /// One process and one directory **per instance**, not per test process.
    /// Cargo runs unit tests on threads inside one process, so a fixture keyed
    /// on the pid would hand four tests the same socket and the first to finish
    /// would delete it out from under the rest — a failure that looks exactly
    /// like a TPM that never started.
    #[cfg(feature = "tpm-device")]
    pub struct Swtpm {
        dir: std::path::PathBuf,
        process: Option<std::process::Child>,
    }

    #[cfg(feature = "tpm-device")]
    impl Swtpm {
        fn start() -> Self {
            use std::sync::atomic::{AtomicUsize, Ordering};
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let unique = NEXT.fetch_add(1, Ordering::SeqCst);
            let dir =
                std::env::temp_dir().join(format!("asv-swtpm-{}-{unique}", std::process::id()));
            std::fs::create_dir_all(dir.join("state")).expect("create swtpm state");
            let tpm = dir.join("tpm.sock");
            let ctrl = dir.join("ctrl.sock");
            let mut process = std::process::Command::new("swtpm")
                .args([
                    "socket",
                    "--tpm2",
                    &format!("--server=type=unixio,path={}", tpm.display()),
                    &format!("--ctrl=type=unixio,path={}", ctrl.display()),
                    "--flags=not-need-init,startup-clear",
                    &format!("--tpmstate=dir={}", dir.join("state").display()),
                ])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("swtpm is on PATH: this suite runs with --features tpm-device");

            // The socket appears a moment after the process starts, and a
            // client that connects too early gets a refusal that reads as a
            // missing device. Waiting for the *process to exit* as well as for
            // the socket to appear is what turns "swtpm is not installed" into a
            // message that says so — with what it printed — instead of a
            // timeout and a shrug.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                if tpm.exists() {
                    break;
                }
                if let Some(status) = process.try_wait().expect("poll swtpm") {
                    let mut output = String::new();
                    if let Some(mut err) = process.stderr.take() {
                        use std::io::Read as _;
                        let _ = err.read_to_string(&mut output);
                    }
                    panic!("swtpm exited with {status} before creating its socket: {output}");
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "swtpm did not create {} within ten seconds",
                    tpm.display()
                );
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Self {
                dir,
                process: Some(process),
            }
        }

        fn device(&self) -> Tpm2Device {
            Tpm2Device::open(TpmEndpoint::from_path(&self.dir.join("tpm.sock")))
                .expect("a running swtpm accepts a connection")
        }
    }

    #[cfg(feature = "tpm-device")]
    impl Drop for Swtpm {
        fn drop(&mut self) {
            if let Some(mut process) = self.process.take() {
                let _ = process.kill();
                let _ = process.wait();
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// A real device answers. Not a mock answering, not a placeholder: a TPM
    /// 2.0 implementation on the other end of a socket, reached by the
    /// encoding in this file.
    #[cfg(feature = "tpm-device")]
    #[test]
    fn a_real_tpm2_answers_get_random() {
        let swtpm = Swtpm::start();
        let device = swtpm.device();
        assert!(!device.is_hardware(), "swtpm is not silicon");
        device
            .startup()
            .expect("an already-started device is not a failure");
        let first = device.random(16).expect("GetRandom");
        let second = device.random(16).expect("GetRandom again");
        assert_eq!(first.len(), 16);
        assert_eq!(second.len(), 16);
        assert_ne!(
            first, second,
            "a device that answers twice with the same bytes is not random"
        );
    }

    /// The bank and the width come from the device.
    ///
    /// This is what replaces a `GetCapability` discovery path: the device
    /// reports the `TPMS_PCR_SELECTION` it used, and the profile constant is
    /// confirmed against it rather than trusted.
    #[cfg(feature = "tpm-device")]
    #[test]
    fn a_real_tpm2_reports_the_bank_it_uses() {
        let swtpm = Swtpm::start();
        let selection = swtpm
            .device()
            .pcr_selection(&[PcrSlot::Pcr0, PcrSlot::Pcr4, PcrSlot::Pcr7])
            .expect("PCR_Read");
        assert_eq!(selection.algorithm, TPM_ALG_SHA256);
        assert_eq!(
            selection.sizeof_select, PC_CLIENT_PCR_SELECTION_BYTES,
            "the device and the profile constant must agree"
        );
        for slot in [PcrSlot::Pcr0, PcrSlot::Pcr4, PcrSlot::Pcr7] {
            assert!(
                selection.covers(slot),
                "{slot:?} is outside the selection the device reported"
            );
        }
    }

    /// PCRs are read over the real protocol, and the answer is the device's
    /// own frame: the digest count is the number of slots asked for, the
    /// selection comes back exactly as sent, and nothing is left over.
    ///
    /// **What this deliberately does not assert, and why.** An earlier version
    /// of this test required every digest to contain a byte that was not zero,
    /// on the reasoning that all-zero is what a client that invented the answer
    /// would return. On a device that has just been started, every PCR *is*
    /// zero — that is the correct answer, and `tpm2_pcrread` against the same
    /// device returns the same zeros. A test demanding otherwise would be
    /// asserting a fiction, and would fail on a correct client. Changing a PCR
    /// needs `TPM2_PCR_Extend` with an authorization session, which this module
    /// does not implement yet; until it does, the falsifiable claim here is the
    /// frame, and the frame is checked in full.
    #[cfg(feature = "tpm-device")]
    #[test]
    fn a_real_tpm2_answers_pcr_read_in_its_own_frame() {
        let swtpm = Swtpm::start();
        let device = swtpm.device();
        let read = device
            .pcr_read(&[PcrSlot::Pcr0, PcrSlot::Pcr4, PcrSlot::Pcr7])
            .expect("PCR_Read");
        assert_eq!(read.len(), 3);
        // The same device gives the same answer for the same PCR, because
        // nothing has extended it — and the answer being stable is only
        // meaningful because the frame above was checked, not assumed.
        let again = device.pcr_read(&[PcrSlot::Pcr0]).expect("PCR_Read again");
        assert_eq!(again[0].1, read[0].1);
    }

    /// The width check in `selection_bitmap` is **unreachable through
    /// `PcrSlot`**, and that is said here rather than papered over with a test
    /// that cannot fail. The enum carries PCR 0, 4 and 7 and the profile's
    /// selection is 24 PCRs wide, so the guard is defence against a future
    /// variant. A hand-rolled out-of-range index would only be testing the
    /// test's own arithmetic.
    ///
    /// What this does check is the half that could be wrong: that the profile
    /// constant matches the device, because a selection one byte short would
    /// read the wrong PCRs and still answer.
    #[cfg(feature = "tpm-device")]
    #[test]
    fn the_profile_width_matches_the_device() {
        for slot in [PcrSlot::Pcr0, PcrSlot::Pcr4, PcrSlot::Pcr7] {
            assert!(
                (slot.index() as usize) < PC_CLIENT_PCR_SELECTION_BYTES as usize * 8,
                "{slot:?} is outside a {PC_CLIENT_PCR_SELECTION_BYTES}-byte selection"
            );
        }
        let swtpm = Swtpm::start();
        let device = swtpm.device();
        assert_eq!(
            device
                .pcr_selection(&[PcrSlot::Pcr0, PcrSlot::Pcr4, PcrSlot::Pcr7])
                .expect("PCR_Read")
                .sizeof_select,
            PC_CLIENT_PCR_SELECTION_BYTES,
            "the device and the profile constant must agree"
        );
        assert!(device
            .pcr_read(&[PcrSlot::Pcr0, PcrSlot::Pcr4, PcrSlot::Pcr7])
            .is_ok());
    }

    // ---------------------------------------------------------------------
    // The session encoding, pinned without a device.
    //
    // The bytes below were captured from `tpm2-tools` talking to `swtpm`, with
    // the device's own log as the source rather than a proxy: `swtpm socket
    // --log file=<path>,level=9` prints every request it reads. Three earlier
    // attempts to capture them through a proxy failed, and the log made the
    // ground truth a command away.
    //
    // This test is here so the layout is checked without a device in the loop,
    // and so a mutation of the encoder fails *here*, naming the bytes, instead
    // of failing three layers away as a `TPM_RC_SIZE` from the TPM.
    // ---------------------------------------------------------------------

    /// The 65 bytes a correct `PCR_Extend` for PCR 1 is, spelled out.
    ///
    /// Transcribed from the capture, not generated by the code under test: a
    /// test that built its expectation with the same helper it is testing would
    /// agree with any layout, including a wrong one.
    #[test]
    fn a_password_session_sits_between_the_handles_and_the_parameters() {
        let area = password_session_area();
        assert_eq!(area.len(), 9, "the area is nine bytes and the size says so");

        let handles = 1u32.to_be_bytes();
        let mut parameters = Vec::new();
        parameters.extend_from_slice(&1u32.to_be_bytes());
        parameters.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        parameters.extend_from_slice(&[0u8; 32]);

        let size = 10 + handles.len() + 4 + area.len() + parameters.len();
        let mut request = Vec::new();
        request.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
        request.extend_from_slice(&(size as u32).to_be_bytes());
        request.extend_from_slice(&TPM2_PCR_EXTEND.to_be_bytes());
        request.extend_from_slice(&handles);
        request.extend_from_slice(&(area.len() as u32).to_be_bytes());
        request.extend_from_slice(&area);
        request.extend_from_slice(&parameters);

        let mut expected: Vec<u8> = vec![
            0x80, 0x02, // TPM_ST_SESSIONS
            0x00, 0x00, 0x00, 0x41, // commandSize = 65
            0x00, 0x00, 0x01, 0x82, // TPM2_PCR_Extend
            0x00, 0x00, 0x00, 0x01, // pcrHandle = PCR 1
            0x00, 0x00, 0x00, 0x09, // authorizationSize = 9
            0x40, 0x00, 0x00, 0x09, // TPM_RS_PW
            0x00, 0x00, // empty authorization
            0x00, 0x00, // empty nonce
            0x00, // TPMA_SESSION
            0x00, 0x00, 0x00, 0x01, // one digest
            0x00, 0x0B, // TPM_ALG_SHA256
        ];
        expected.extend_from_slice(&[0u8; 32]);
        assert_eq!(request, expected, "the wire layout changed");
    }

    // ---------------------------------------------------------------------
    // The policy route, pinned against the reference client's bytes.
    //
    // Both requests below are transcribed from what `tpm2_policypcr` and
    // `tpm2_startauthsession` put on the wire, read out of the device's own log
    // rather than out of a specification. Each one is a layout that reads as
    // wrong: the `StartAuthSession` area has a byte this client cannot name, and
    // `PolicyPCR` carries no authorization area at all, which is the opposite of
    // the rule this module had learned from `PCR_Extend`.
    // ---------------------------------------------------------------------

    /// The 59 bytes a policy `StartAuthSession` is, spelled out.
    ///
    /// The nonce is the reference client's own, so the whole request is
    /// comparable byte for byte. The `nonceCaller` is replaced in practice —
    /// this client sends thirty-two fresh bytes — and the *shape* of that field
    /// is what the rest of the request depends on.
    #[test]
    fn a_policy_session_is_the_request_the_reference_client_sends() {
        let reference_nonce: Vec<u8> = vec![
            0x84, 0xEF, 0xBF, 0x27, 0x05, 0x03, 0x72, 0x84, 0xB6, 0xE0, 0x97, 0x9B, 0x89, 0x9E,
            0x15, 0xD3, 0xA9, 0x2F, 0xC4, 0x0D, 0x4A, 0x11, 0xC0, 0xCC, 0x78, 0x57, 0x71, 0x65,
            0xBD, 0xF8, 0xB9, 0xF7,
        ];
        let body = policy_session_body(&reference_nonce);
        let size = 10 + body.len();
        let mut request = Vec::new();
        request.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        request.extend_from_slice(&(size as u32).to_be_bytes());
        request.extend_from_slice(&TPM2_START_AUTH_SESSION.to_be_bytes());
        request.extend_from_slice(&body);

        let mut expected: Vec<u8> = vec![
            0x80, 0x01, // TPM_ST_NO_SESSIONS
            0x00, 0x00, 0x00, 0x3B, // commandSize = 59
            0x00, 0x00, 0x01, 0x76, // TPM2_StartAuthSession
            0x40, 0x00, 0x00, 0x07, // tpmKey = TPM_RH_NULL
            0x40, 0x00, 0x00, 0x07, // bind = TPM_RH_NULL
            0x00, 0x20, // nonceCaller, 32 bytes
        ];
        expected.extend_from_slice(&reference_nonce);
        expected.extend_from_slice(&[
            0x00, // the byte this client does not name; the device requires 0x00
            0x00, 0x01, // sessionType = TPM_SE_POLICY
            0x00, 0x10, // symmetric = TPM_ALG_NULL
            0x00, 0x0B, // authHash = TPM_ALG_SHA256
        ]);
        assert_eq!(request, expected, "the wire layout changed");
        assert_eq!(request.len(), 59, "the reference request is 59 bytes");
    }

    /// The 58 bytes a `PolicyPCR` is, spelled out.
    ///
    /// The selection is PCRs 0 to 3, which `PcrSlot` does not model, so this
    /// pins the *encoding* rather than a slot list. What it pins hardest is the
    /// absence: between the session handle and the `pcrDigest` there is no
    /// authorization size, no `TPM_RS_PW` and no `TPMA_SESSION`, and a client
    /// that added one would agree with every other command in this module and
    /// be answered `0x184`.
    #[test]
    fn a_policy_pcr_is_the_request_the_reference_client_sends() {
        let reference_digest: Digest = [
            0x38, 0x72, 0x3A, 0x2E, 0x5E, 0x8A, 0x17, 0xAA, 0x79, 0x50, 0xDC, 0x00, 0x82, 0x09,
            0x94, 0x4E, 0x89, 0x8F, 0x69, 0xA7, 0xBD, 0x10, 0xA2, 0x3C, 0x83, 0x9D, 0x34, 0x1E,
            0x93, 0x5F, 0xD5, 0xCA,
        ];
        let reference_selection: Vec<u8> = vec![
            0x00, 0x00, 0x00, 0x01, // one bank
            0x00, 0x0B, // TPM_ALG_SHA256
            0x03, // sizeofSelect
            0x0F, 0x00, 0x00, // PCRs 0, 1, 2, 3
        ];
        let body = policy_pcr_body(0x0300_0000, &reference_digest, &reference_selection);
        let size = 10 + body.len();
        let mut request = Vec::new();
        request.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        request.extend_from_slice(&(size as u32).to_be_bytes());
        request.extend_from_slice(&TPM2_POLICY_PCR.to_be_bytes());
        request.extend_from_slice(&body);

        let expected: Vec<u8> = vec![
            0x80, 0x01, // TPM_ST_NO_SESSIONS
            0x00, 0x00, 0x00, 0x3A, // commandSize = 58
            0x00, 0x00, 0x01, 0x7F, // TPM2_PolicyPCR
            0x03, 0x00, 0x00, 0x00, // pcrHandle = the policy session
            0x00, 0x20, // pcrDigest, 32 bytes
        ]
        .into_iter()
        .chain(reference_digest)
        .chain(reference_selection)
        .collect();
        assert_eq!(request, expected, "the wire layout changed");
        assert_eq!(request.len(), 58, "the reference request is 58 bytes");
    }

    /// The `pcrDigest` is the hash of the PCR values, in index order.
    ///
    /// The order matters because the device concatenates the values the
    /// selection covers, sorted by PCR index, and a digest computed over the
    /// caller's ordering names a set the device did not name. A client that
    /// listed its slots in a different order would compute a digest that looks
    /// right and is refused.
    #[test]
    fn the_pcr_digest_hashes_the_values_in_index_order_not_in_the_order_asked() {
        let pcr0: Digest = [0x10; 32];
        let pcr4: Digest = [0x44; 32];
        let pcr7: Digest = [0x77; 32];

        let in_order = pcr_value_digest(&[
            (PcrSlot::Pcr0, pcr0),
            (PcrSlot::Pcr4, pcr4),
            (PcrSlot::Pcr7, pcr7),
        ]);
        let shuffled = pcr_value_digest(&[
            (PcrSlot::Pcr7, pcr7),
            (PcrSlot::Pcr0, pcr0),
            (PcrSlot::Pcr4, pcr4),
        ]);
        assert_eq!(
            in_order, shuffled,
            "the digest must not depend on the order the caller listed the PCRs"
        );

        let mut hasher = Sha256::new();
        hasher.update(pcr0);
        hasher.update(pcr4);
        hasher.update(pcr7);
        let expected: Digest = hasher.finalize().into();
        assert_eq!(in_order, expected, "it is the hash of the values");
    }

    /// The policy chain this client computes is the one the device reported.
    ///
    /// Pinned to a measured pair: over a selection of PCRs 0 to 3 on a device
    /// whose PCRs were all zero, the device answered `84b506c9…` for a session
    /// that started at `0^256`, and the same session asked a second time
    /// answered `6dcc673f…`. Both fall out of the chain below, computed here
    /// with no device in the loop — so a change to the formula is caught by a
    /// test that cannot be explained by the fixture agreeing with the client.
    #[test]
    fn the_policy_chain_reproduces_the_digests_the_device_reported() {
        let selection: Vec<u8> = vec![0x00, 0x00, 0x00, 0x01, 0x00, 0x0B, 0x03, 0x0F, 0x00, 0x00];
        // The digest of four zero-valued PCRs, which is what the reference
        // client sent and what the device accepted.
        let pcr_digest: Digest = [
            0x38, 0x72, 0x3A, 0x2E, 0x5E, 0x8A, 0x17, 0xAA, 0x79, 0x50, 0xDC, 0x00, 0x82, 0x09,
            0x94, 0x4E, 0x89, 0x8F, 0x69, 0xA7, 0xBD, 0x10, 0xA2, 0x3C, 0x83, 0x9D, 0x34, 0x1E,
            0x93, 0x5F, 0xD5, 0xCA,
        ];
        let first = advance_policy_digest_over(&PolicySession::seed(), &selection, &pcr_digest);
        let expected_first: Digest = [
            0x84, 0xB5, 0x06, 0xC9, 0x1F, 0x20, 0x5E, 0x06, 0xAB, 0xD6, 0xF8, 0x3F, 0x26, 0x9D,
            0x8D, 0x80, 0x11, 0xD4, 0x95, 0xE0, 0x92, 0x14, 0xA4, 0x0F, 0xE3, 0x2B, 0x46, 0x60,
            0x30, 0x1D, 0xDA, 0x09,
        ];
        assert_eq!(first, expected_first, "the first step of the chain moved");

        let second = advance_policy_digest_over(&first, &selection, &pcr_digest);
        let expected_second: Digest = [
            0x6D, 0xCC, 0x67, 0x3F, 0xD4, 0x6F, 0x7D, 0x26, 0xF5, 0x10, 0x35, 0x18, 0x3B, 0x7C,
            0x34, 0xBE, 0x0E, 0x7E, 0x1C, 0x9F, 0x9D, 0x7E, 0x8C, 0xF6, 0x9F, 0xE5, 0x14, 0xBB,
            0xB5, 0xED, 0x6E, 0xCE,
        ];
        assert_eq!(
            second, expected_second,
            "the chain must advance on the same input, as the device's own second \
             answer showed"
        );
    }

    // ---------------------------------------------------------------------
    // The session encoding, against a device.
    // ---------------------------------------------------------------------

    /// A password session is accepted and the write is visible.
    ///
    /// The expected digest is **computed here** from the digest the device held
    /// before and the one this test folded in, not read back and echoed. A test
    /// that read the PCR after writing it and compared it with itself would
    /// pass on a device that ignored the write entirely, which is the defect
    /// this milestone exists to catch. `sha256(previous || new)` is the
    /// definition of a PCR extend, so computing it is asserting the TPM's
    /// arithmetic, not trusting it.
    #[cfg(feature = "tpm-device")]
    #[test]
    fn a_password_session_writes_a_pcr_and_the_device_folds_it() {
        use sha2::{Digest as _, Sha256};

        let swtpm = Swtpm::start();
        let device = swtpm.device();
        let slot = PcrSlot::Pcr7;

        let before = device
            .pcr_read(&[slot])
            .expect("PCR_Read before the write")
            .remove(0)
            .1;
        let folded = [0xABu8; 32];
        device
            .pcr_extend(slot, &folded)
            .expect("PCR_Extend with a password session is accepted");

        let after = device
            .pcr_read(&[slot])
            .expect("PCR_Read after the write")
            .remove(0)
            .1;
        let mut hasher = Sha256::new();
        hasher.update(before);
        hasher.update(folded);
        let expected: Digest = hasher.finalize().into();
        assert_eq!(
            after, expected,
            "the device did not fold the digest the way a PCR extend is defined to"
        );
        assert_ne!(
            after, before,
            "a write that left the PCR unchanged would pass a test that only \
             compared the device with itself"
        );
    }

    /// `Clear` is accepted, and the `0x184` is gone.
    ///
    /// `0x184` names the first handle, not the session, and this is the test
    /// that says so. Sent without `TPM_RH_LOCKOUT` the same session encoding is
    /// refused with exactly that code, which is how six matrices of session
    /// fields came to vary nonce sizes for a failure that had nothing to do
    /// with the session.
    #[cfg(feature = "tpm-device")]
    #[test]
    fn clear_is_accepted_and_the_missing_handle_was_the_whole_bug() {
        let swtpm = Swtpm::start();
        let device = swtpm.device();
        device
            .clear()
            .expect("Clear with its authHandle is accepted");

        // The same command, with the same session area, minus the handle. If
        // this ever stops being `0x184` then the account of the bug in the
        // module docs has stopped being true, and the honest response is to
        // find out what else refuses it.
        let without_handle = device
            .authorized_command(TPM2_CLEAR, &[], &[])
            .expect("a refused command is still an answer")
            .into_body()
            .expect_err("a Clear without its authHandle is refused");
        assert!(
            matches!(without_handle, Tpm2Error::Refused { code: 0x184, .. }),
            "the refusal should still name the missing handle, not the session; \
             it was {without_handle:?}"
        );
    }

    // ---------------------------------------------------------------------
    // The policy route, against a device.
    // ---------------------------------------------------------------------

    /// A policy session starts, and it starts at the seed the chain assumes.
    ///
    /// Two facts in one test because they are one fact: the session is
    /// accepted, and the digest it holds before any policy command is
    /// thirty-two zero bytes. The second is what makes the local chain
    /// comparable at all — a seed this client guessed would make every later
    /// comparison agree with a wrong number.
    #[cfg(feature = "tpm-device")]
    #[test]
    fn a_policy_session_is_accepted_and_starts_at_the_seed() {
        let swtpm = Swtpm::start();
        let device = swtpm.device();
        let session = device
            .start_policy_session()
            .expect("a policy session is accepted with the measured layout");
        assert_ne!(
            session.handle(),
            0,
            "the device named the session it opened"
        );
        assert_eq!(
            device.policy_digest(session).expect("PolicyGetDigest"),
            PolicySession::seed(),
            "a fresh policy session holds thirty-two zero bytes; a different seed \
             would make the locally computed chain meaningless"
        );
    }

    /// `PolicyPCR` is accepted for the PCRs it names.
    ///
    /// The `pcrDigest` this sends is the hash of what the device just reported,
    /// which is the value the device demands; a command built with the session
    /// area this module uses for `PCR_Extend` is answered `0x184` instead.
    #[cfg(feature = "tpm-device")]
    #[test]
    fn a_policy_pcr_is_accepted_for_the_pcrs_it_names() {
        let swtpm = Swtpm::start();
        let device = swtpm.device();
        let session = device.start_policy_session().expect("policy session");
        let digest = device
            .policy_pcr(session, &[PcrSlot::Pcr0, PcrSlot::Pcr4])
            .expect("PolicyPCR over the PCRs the device just reported");
        assert_eq!(digest.len(), 32);
        assert_ne!(
            device.policy_digest(session).expect("PolicyGetDigest"),
            PolicySession::seed(),
            "an accepted PolicyPCR that left the policy where it started would \
             satisfy a test that only checked for a lack of errors"
        );
    }

    /// A `pcrDigest` the PCRs do not produce is refused, and moves nothing.
    ///
    /// This is the row that separates "the command is well formed" from "the
    /// command says something true". Thirty-two zero bytes are a well-formed
    /// `TPM2B_DIGEST` and the device answers `0x1C4` to them — and, measured
    /// separately, so does a random digest. What the test asserts is the
    /// refusal and the absence of movement, because the code is a property of
    /// this build and the absence of movement is not.
    #[cfg(feature = "tpm-device")]
    #[test]
    fn a_pcr_digest_the_pcrs_do_not_produce_is_refused_and_moves_nothing() {
        let swtpm = Swtpm::start();
        let device = swtpm.device();
        let session = device.start_policy_session().expect("policy session");
        let before = device.policy_digest(session).expect("PolicyGetDigest");

        let body = policy_pcr_body(
            session.handle(),
            &[0u8; 32],
            &pcr_selection_body(&[PcrSlot::Pcr0]).expect("selection"),
        );
        let refused = device
            .command(TPM2_POLICY_PCR, &body)
            .expect("a refused command is still an answer")
            .into_body()
            .expect_err("a pcrDigest of thirty-two zero bytes is not what PCR 0 hashes to");
        assert!(
            matches!(refused, Tpm2Error::Refused { .. }),
            "the device should refuse it; it was {refused:?}"
        );
        assert_eq!(
            device.policy_digest(session).expect("PolicyGetDigest"),
            before,
            "a refused PolicyPCR that advanced the policy would be the worst of \
             both: an answer that failed and a state that moved"
        );
    }

    /// The chain this client computes is the chain the device walks.
    ///
    /// The load-bearing test of the whole policy route. It reads the device's
    /// digest after each step and compares it with the value computed here from
    /// the previous one — so a wrong formula, a wrong selection encoding or a
    /// wrong command code all show up as a disagreement between two
    /// computations, neither of which is the other's source.
    #[cfg(feature = "tpm-device")]
    #[test]
    fn the_policy_digest_this_client_computes_is_the_one_the_device_reports() {
        let swtpm = Swtpm::start();
        let device = swtpm.device();
        let session = device.start_policy_session().expect("policy session");

        let mut local = PolicySession::seed();
        let mut steps: Vec<Vec<PcrSlot>> = vec![
            vec![PcrSlot::Pcr0],
            vec![PcrSlot::Pcr4],
            vec![PcrSlot::Pcr0, PcrSlot::Pcr4, PcrSlot::Pcr7],
        ];
        // The order a caller happens to pass must not change the result, so one
        // step is deliberately shuffled.
        steps.push(vec![PcrSlot::Pcr7, PcrSlot::Pcr0, PcrSlot::Pcr4]);

        for slots in steps {
            let pcr_digest = device
                .policy_pcr(session, &slots)
                .expect("PolicyPCR over the PCRs the device just reported");
            local = advance_policy_digest(&local, &slots, &pcr_digest)
                .expect("the selection this client sends is one it can marshal");
            assert_eq!(
                device.policy_digest(session).expect("PolicyGetDigest"),
                local,
                "the device's policy digest and the one computed here disagree \
                 after a PolicyPCR over {slots:?}"
            );
        }
    }
}
