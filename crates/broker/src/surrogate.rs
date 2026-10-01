//! Surrogate registry: the token an agent holds instead of a credential
//! (M4 design D3, D4, D8).
//!
//! A surrogate is a bearer-shaped string that stands in for a `CredentialId`
//! on the wire. The agent can present it; the broker decides whether it means
//! anything. Four properties carry the whole design, and each one is a
//! response to a specific way this goes wrong:
//!
//! 1. **Session-bound.** A surrogate is only ever looked up through the
//!    session that minted it, so a token stolen from one agent is useless to
//!    another even if the process is the same.
//! 2. **Class-bound.** The record remembers what *kind* of credential it
//!    stands for, and redemption asks what kind of operation it is being
//!    spent on. A token minted from a database password cannot back a GitHub
//!    call. This is ADR-0011's `audience-bound`, which the registry
//!    documented for a long time and did not implement (H2).
//! 3. **Bounded in time and in uses.** A surrogate with an unbounded lifetime
//!    or use count is a permanent credential with extra steps, which is the
//!    shape ADR-0011 exists to prevent.
//! 4. **Compared in constant time.** A byte-by-byte `==` on a token leaks its
//!    prefix to an attacker who can time the rejection, which is enough to
//!    forge one token from guesses about another.
//!
//! The registry never stores a secret, only the `CredentialId` the surrogate
//! stands for. That is D8: rotation is structural rather than a cache
//! invalidation problem, because there is no cache to invalidate.

use std::time::{SystemTime, UNIX_EPOCH};

use asv_domain::{AgentSessionId, CredentialClass, CredentialId, OperationFamily};
use rand::RngCore;
use subtle::ConstantTimeEq;

use asv_ipc_protocol::{MAX_SURROGATE_TTL_SECS, MAX_SURROGATE_USES};

/// Prefix that makes a surrogate recognizable in a log or a crash dump, so
/// one is never mistaken for a real credential during triage.
const SURROGATE_PREFIX: &str = "asv1_";

/// Bytes of entropy behind a surrogate. 32 bytes is the width ADR-0011 asks
/// for; below that a brute force becomes conceivable against a service that
/// allows unlimited attempts.
const SURROGATE_ENTROPY_BYTES: usize = 32;

/// One minted surrogate and everything needed to decide whether it still
/// means anything.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SurrogateRecord {
    /// The session this surrogate belongs to. A surrogate presented under a
    /// different session is refused even if the token itself is valid.
    session: AgentSessionId,
    /// What the surrogate stands in for. Never the secret.
    credential: CredentialId,
    /// The class of thing `credential` is, so the token can be refused for an
    /// operation it is the wrong shape for.
    ///
    /// This is the `audience-bound` property ADR-0011 promises. Before it
    /// existed, a surrogate minted from a database password redeemed happily
    /// against `ReadIssue` and the broker dialled GitHub with it (H2).
    /// It is a *type* bound rather than a policy decision, which is why it
    /// costs a comparison and not a Cedar evaluation.
    class: CredentialClass,
    /// Absolute expiry as a UNIX timestamp in seconds. Absolute rather than a
    /// deadline computed at mint time, so the record is self-describing and a
    /// clock change cannot silently extend or collapse a window.
    expires_at: u64,
    /// Remaining permitted uses.
    remaining_uses: u32,
}

/// Why a surrogate was refused.
///
/// Every variant is a refusal. There is no "accepted but degraded" outcome,
/// because a partially valid token is how a forgery attempt turns into a real
/// request.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SurrogateError {
    #[error("no surrogate matches the presented token")]
    Unknown,

    #[error("surrogate expired")]
    Expired,

    #[error("surrogate has no uses remaining")]
    Exhausted,

    #[error("surrogate was minted for a different session")]
    WrongSession,

    #[error("surrogate stands for a credential of the wrong class for this operation")]
    WrongClass,
}

/// The broker-side surrogate table.
///
/// A `Vec`, not a `HashMap`, and that is a deliberate consequence of the
/// constant-time requirement below: scanning every entry is what makes lookup
/// timing-independent, and a hash map would either reintroduce the early exit
/// or force a second keyed lookup after the scan, which is the same signal in
/// a different place. The table is bounded by construction (a cap on uses, a
/// cap on TTL, and a sweep), and the number of live surrogates is the number
/// of concurrent agent sessions, which is small.
#[derive(Debug, Default)]
pub struct SurrogateRegistry {
    records: Vec<(String, SurrogateRecord)>,
}

impl SurrogateRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mints a surrogate bound to `session` for `credential`.
    ///
    /// `ttl_secs` and `max_uses` are *requests*, not grants: both are clamped
    /// to the protocol ceilings, because a client that could choose its own
    /// limits would make every bound on this token advisory. A request for
    /// zero uses mints nothing usable, so it is clamped up to one rather than
    /// producing a token that always fails and looks like a bug.
    ///
    /// `class` is recorded rather than derived here, because the registry has
    /// no vault and cannot know what a `CredentialId` is. The caller resolves
    /// it from the credential's metadata; making it a parameter keeps this
    /// module free of the vault and keeps the decision visible at the one
    /// place that has the facts.
    pub fn mint(
        &mut self,
        session: AgentSessionId,
        credential: CredentialId,
        class: CredentialClass,
        ttl_secs: u64,
        max_uses: u32,
        now: u64,
    ) -> Result<(String, u64, u32), SurrogateError> {
        let ttl = ttl_secs.clamp(1, MAX_SURROGATE_TTL_SECS);
        let uses = max_uses.clamp(1, MAX_SURROGATE_USES);
        let expires_at = now.saturating_add(ttl);
        let token = format!("{SURROGATE_PREFIX}{}", self.random_token());

        self.records.push((
            token.clone(),
            SurrogateRecord {
                session,
                credential,
                class,
                expires_at,
                remaining_uses: uses,
            },
        ));
        Ok((token, expires_at, uses))
    }

    /// Resolves a presented token to the credential it stands for, consuming
    /// one use, and refuses it if the credential is the wrong class for
    /// `required`.
    ///
    /// Order matters and is deliberate: the token is matched, then the session
    /// is checked, then the class, then expiry, then the budget. A record that
    /// is both expired and out of uses reports as expired, because the
    /// shorter-lived failure is the more informative one for an operator
    /// reading the log.
    ///
    /// The class check sits *before* the use is consumed, so a token cannot be
    /// spent by presenting it at the wrong kind of operation and then run out
    /// of budget on the operation it was actually minted for.
    pub fn redeem_for(
        &mut self,
        presented: &str,
        session: AgentSessionId,
        required: OperationFamily,
        now: u64,
    ) -> Result<CredentialId, SurrogateError> {
        let Some(index) = self.constant_time_lookup(presented) else {
            return Err(SurrogateError::Unknown);
        };
        let record = &self.records[index].1;

        // The session binding is an equality on an opaque id, not on attacker-
        // chosen bytes, so a constant-time compare would buy nothing here. What
        // is attacker-chosen is the token, and that comparison already ran in
        // constant time above.
        if record.session != session {
            return Err(SurrogateError::WrongSession);
        }
        // Also not attacker-chosen: the class was resolved from the vault at
        // mint time and the family is the handler's own constant. The only
        // attacker-chosen input in this function is `presented`, compared in
        // constant time above.
        if !record.class.backs(required) {
            return Err(SurrogateError::WrongClass);
        }
        if now >= record.expires_at {
            return Err(SurrogateError::Expired);
        }
        if record.remaining_uses == 0 {
            return Err(SurrogateError::Exhausted);
        }

        self.records[index].1.remaining_uses -= 1;
        Ok(self.records[index].1.credential)
    }

    /// Finds a token without leaking its prefix through timing.
    ///
    /// A hash lookup returns as soon as it finds a match, so an attacker
    /// measuring rejections could recover the token byte by byte. This visits
    /// every record and compares with `ct_eq`, which runs in time independent
    /// of where the first difference is.
    fn constant_time_lookup(&self, presented: &str) -> Option<usize> {
        let presented = presented.as_bytes();
        let mut found = None;
        for (index, (token, _)) in self.records.iter().enumerate() {
            let candidate = token.as_bytes();
            // A length mismatch short-circuits the comparison to false, so a
            // shorter or longer guess can never match.
            let equal =
                candidate.len() == presented.len() && bool::from(candidate.ct_eq(presented));
            // No early exit: the loop must visit every record regardless of
            // whether a match was already seen, or the running time still
            // depends on the answer.
            found = if equal { Some(index) } else { found };
        }
        found
    }

    /// Drops a surrogate without consuming a use. Reports whether it existed,
    /// so a caller can distinguish "revoked" from "never existed" instead of
    /// silently succeeding.
    ///
    /// Scoped to the owning session on purpose: a revoke that ignored the
    /// session would let one session destroy another's token, turning a
    /// availability bug into a cross-session denial of service.
    pub fn revoke(&mut self, presented: &str, session: AgentSessionId) -> bool {
        match self.constant_time_lookup(presented) {
            Some(index) => {
                if self.records[index].1.session != session {
                    return false;
                }
                self.records.swap_remove(index);
                true
            }
            None => false,
        }
    }

    /// Drops every surrogate belonging to `session`.
    ///
    /// Called when a session ends. Leaving a token live after its session is
    /// gone would mean the session lifetime is not a real boundary, and the
    /// `revoke_session` path in the policy engine would be a lie.
    pub fn revoke_session(&mut self, session: AgentSessionId) -> usize {
        let before = self.records.len();
        self.records.retain(|(_, record)| record.session != session);
        before - self.records.len()
    }

    /// Drops every surrogate that stands for `credential`, and reports how
    /// many went.
    ///
    /// Scoped by credential rather than by session, because a revocation is
    /// about the secret and not about who is holding a token for it: an agent
    /// that minted before the operator revoked is exactly the holder this is
    /// for, and scoping to the revoking session would leave those behind.
    ///
    /// **This is not the control that makes revocation stick.** The vault
    /// refuses the secret on its own — `with_secret` gates on the in-memory
    /// body, which the same `transact` that wrote the deletion has already
    /// emptied — so a token left here would already be worthless. What this
    /// buys is that the registry stops *claiming* those tokens are live, and
    /// that the failure an agent meets is a clean refusal at revoke time
    /// rather than a "no such credential" surprise when it spends a token it
    /// was told it still had.
    pub fn revoke_credential(&mut self, credential: CredentialId) -> usize {
        let before = self.records.len();
        self.records
            .retain(|(_, record)| record.credential != credential);
        before - self.records.len()
    }

    /// Removes every expired record and reports how many went.
    ///
    /// Separate from the read path on purpose: sweeping on redeem would make
    /// a lookup's cost depend on unrelated garbage, and never sweeping would
    /// grow the table without bound.
    pub fn sweep(&mut self, now: u64) -> usize {
        let before = self.records.len();
        self.records.retain(|(_, record)| now < record.expires_at);
        before - self.records.len()
    }

    /// Live record count. UAT-030 asserts this is zero after teardown, so it
    /// counts records rather than sessions.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// 32 bytes from the OS RNG, base64url-encoded.
    ///
    /// `rand::thread_rng` is seeded from the OS, so this is not a predictable
    /// stream; the base64url alphabet keeps the token free of characters that
    /// would need escaping in a header or a log line.
    fn random_token(&self) -> String {
        let mut bytes = [0u8; SURROGATE_ENTROPY_BYTES];
        rand::thread_rng().fill_bytes(&mut bytes);
        base64url(&bytes)
    }
}

/// The current UNIX time in seconds, saturating to 0 before the epoch rather
/// than panicking. A broker whose clock has not settled should mint a
/// surrogate that is immediately expired, not one that panics.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Standard base64url without padding.
///
/// Written out rather than pulled in as a dependency: this is the only
/// encoding the crate needs, and a single-purpose function is cheaper to audit
/// than a new dependency in a crate that holds credential-shaped state.
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(triple >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(triple >> 12) as usize & 0x3f] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(triple >> 6) as usize & 0x3f] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[triple as usize & 0x3f] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 1_700_000_000;

    fn session() -> AgentSessionId {
        AgentSessionId::new()
    }

    fn credential() -> CredentialId {
        CredentialId::new()
    }

    fn minted() -> (String, CredentialId) {
        let session = session();
        let credential = credential();
        let (token, _, _) = SurrogateRegistry::new()
            .mint(session, credential, CredentialClass::Generic, 60, 3, T0)
            .expect("mint succeeds");
        (token, credential)
    }

    /// The shape of a surrogate is load-bearing: it must be recognizable as a
    /// surrogate so triage never confuses it with a leaked provider token, and
    /// it must carry enough entropy to be unguessable.
    #[test]
    fn a_surrogate_is_prefixed_and_wide() {
        let (token, _) = minted();
        assert!(token.starts_with(SURROGATE_PREFIX), "{token}");
        // 32 bytes of base64url is 43 characters, unpadded.
        let body = token.strip_prefix(SURROGATE_PREFIX).expect("prefixed");
        assert_eq!(body.len(), 43, "{body}");
        assert!(
            body.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "token must stay in the header-safe alphabet: {body}"
        );
    }

    /// Two mints must not collide. A collision would mean one agent's
    /// surrogate authorizes another's operation.
    #[test]
    fn two_mints_produce_different_tokens() {
        let mut registry = SurrogateRegistry::new();
        let (first, _, _) = registry
            .mint(session(), credential(), CredentialClass::Generic, 60, 1, T0)
            .expect("mint");
        let (second, _, _) = registry
            .mint(session(), credential(), CredentialClass::Generic, 60, 1, T0)
            .expect("mint");
        assert_ne!(first, second);
    }

    /// A surrogate redeems to the credential it stands for, and only while it
    /// still has budget.
    #[test]
    fn redeeming_consumes_exactly_the_granted_uses() {
        let session = session();
        let credential = credential();
        let mut registry = SurrogateRegistry::new();
        let (token, _, uses) = registry
            .mint(session, credential, CredentialClass::Generic, 60, 3, T0)
            .expect("mint");
        assert_eq!(uses, 3);

        for _ in 0..3 {
            assert_eq!(
                registry.redeem_for(&token, session, OperationFamily::GitHub, T0 + 1),
                Ok(credential),
                "a use within budget must redeem"
            );
        }
        assert_eq!(
            registry.redeem_for(&token, session, OperationFamily::GitHub, T0 + 1),
            Err(SurrogateError::Exhausted),
            "the fourth attempt must be refused"
        );
    }

    /// Replay is the attack this whole module exists for. A captured token
    /// presented again after its budget is spent must not work.
    #[test]
    fn a_captured_token_cannot_be_replayed() {
        let session = session();
        let credential = credential();
        let mut registry = SurrogateRegistry::new();
        let (token, _, _) = registry
            .mint(session, credential, CredentialClass::Generic, 60, 1, T0)
            .expect("mint");

        // The legitimate use succeeds.
        assert_eq!(
            registry.redeem_for(&token, session, OperationFamily::GitHub, T0),
            Ok(credential)
        );
        // An attacker replaying the same captured token does not.
        assert_eq!(
            registry.redeem_for(&token, session, OperationFamily::GitHub, T0),
            Err(SurrogateError::Exhausted)
        );
    }

    /// Expiry is checked against the clock, and a token one second past its
    /// window is refused. The boundary is `now >= expires_at`, so a token is
    /// dead exactly at its expiry, not a second later.
    #[test]
    fn a_surrogate_dies_exactly_at_its_expiry() {
        let session = session();
        let mut registry = SurrogateRegistry::new();
        let (token, _, _) = registry
            .mint(session, credential(), CredentialClass::Generic, 60, 5, T0)
            .expect("mint");

        assert!(
            registry
                .redeem_for(&token, session, OperationFamily::GitHub, T0 + 59)
                .is_ok(),
            "one second early"
        );
        assert_eq!(
            registry.redeem_for(&token, session, OperationFamily::GitHub, T0 + 60),
            Err(SurrogateError::Expired),
            "at the boundary the token must be dead"
        );
    }

    /// The client proposes a TTL, the broker clamps it. A token that outlives
    /// the cap would make expiry advisory.
    #[test]
    fn a_client_cannot_mint_a_surrogate_that_outlives_the_cap() {
        let session = session();
        let mut registry = SurrogateRegistry::new();
        let (token, expires_at, _) = registry
            .mint(
                session,
                credential(),
                CredentialClass::Generic,
                u64::MAX,
                1,
                T0,
            )
            .expect("mint");
        assert_eq!(
            expires_at,
            T0 + MAX_SURROGATE_TTL_SECS,
            "an absurd TTL must be clamped, not honoured"
        );
        // Alive one second before the cap, dead exactly at it.
        assert!(registry
            .redeem_for(
                &token,
                session,
                OperationFamily::GitHub,
                T0 + MAX_SURROGATE_TTL_SECS - 1
            )
            .is_ok());
        assert_eq!(
            registry.redeem_for(
                &token,
                session,
                OperationFamily::GitHub,
                T0 + MAX_SURROGATE_TTL_SECS
            ),
            Err(SurrogateError::Expired),
            "the cap is a boundary, not a suggestion"
        );
    }

    /// The use budget is clamped the same way, and the clamp is observable by
    /// counting real redemptions rather than by reading the returned number.
    #[test]
    fn a_client_cannot_mint_an_unbounded_use_budget() {
        let session = session();
        let mut registry = SurrogateRegistry::new();
        let (token, _, reported) = registry
            .mint(
                session,
                credential(),
                CredentialClass::Generic,
                60,
                u32::MAX,
                T0,
            )
            .expect("mint");
        assert_eq!(
            reported, MAX_SURROGATE_USES,
            "the reported budget is clamped"
        );

        // Counting the actual redemptions is the part that matters: a broker
        // that reports a clamped number and then honours u32::MAX would pass an
        // assertion on the return value alone.
        for attempt in 0..MAX_SURROGATE_USES {
            assert!(
                registry
                    .redeem_for(&token, session, OperationFamily::GitHub, T0)
                    .is_ok(),
                "use {attempt} is within the clamped budget"
            );
        }
        assert_eq!(
            registry.redeem_for(&token, session, OperationFamily::GitHub, T0),
            Err(SurrogateError::Exhausted),
            "the budget is the cap, not the request"
        );
    }

    /// A zero request is clamped up to one usable use. Minting a token that can
    /// never work would look like a broker bug rather than a client error.
    #[test]
    fn a_zero_request_is_clamped_to_one_usable_use() {
        let session = session();
        let credential = credential();
        let mut registry = SurrogateRegistry::new();
        let (token, _, uses) = registry
            .mint(session, credential, CredentialClass::Generic, 0, 0, T0)
            .expect("mint");
        assert_eq!(uses, 1);
        assert_eq!(
            registry.redeem_for(&token, session, OperationFamily::GitHub, T0),
            Ok(credential)
        );
    }

    /// A token minted for one session must not work under another, even from
    /// the same process. This is the session-binding property.
    #[test]
    fn a_surrogate_is_bound_to_its_minting_session() {
        let owner = session();
        let mut registry = SurrogateRegistry::new();
        let (token, _, _) = registry
            .mint(owner, credential(), CredentialClass::Generic, 60, 5, T0)
            .expect("mint");

        assert_eq!(
            registry.redeem_for(&token, session(), OperationFamily::GitHub, T0),
            Err(SurrogateError::WrongSession),
            "another session must not redeem a valid token"
        );
        assert!(
            registry
                .redeem_for(&token, owner, OperationFamily::GitHub, T0)
                .is_ok(),
            "the owner still can"
        );
    }

    /// A guess must be refused as unknown, not as exhausted or expired. The
    /// distinction matters: an attacker learns nothing about which failure mode
    /// their guess triggered.
    #[test]
    fn an_unknown_token_is_refused_without_detail() {
        let mut registry = SurrogateRegistry::new();
        registry
            .mint(session(), credential(), CredentialClass::Generic, 60, 1, T0)
            .expect("mint");
        for guess in [
            "asv1_not-a-real-token",
            "asv1",
            "",
            "not-even-prefixed",
            "ASV1_CASE_MISMATCH",
        ] {
            assert_eq!(
                registry.redeem_for(guess, session(), OperationFamily::GitHub, T0),
                Err(SurrogateError::Unknown),
                "{guess} must be refused as unknown"
            );
        }
    }

    /// Revoking a credential must kill every token that stands for it, from
    /// every session, and must report how many died so the broker can tell the
    /// operator what was in flight.
    #[test]
    fn revoking_a_credential_revokes_every_token_for_it() {
        let doomed = credential();
        let bystander = credential();
        let first = session();
        let second = session();
        let mut registry = SurrogateRegistry::new();
        let (first_token, _, _) = registry
            .mint(first, doomed, CredentialClass::Generic, 60, 5, T0)
            .expect("mint");
        let (second_token, _, _) = registry
            .mint(second, doomed, CredentialClass::Generic, 60, 5, T0)
            .expect("mint");
        let (bystander_token, _, _) = registry
            .mint(first, bystander, CredentialClass::Generic, 60, 5, T0)
            .expect("mint");

        assert_eq!(registry.revoke_credential(doomed), 2, "both went");

        for token in [&first_token, &second_token] {
            assert_eq!(
                registry.redeem_for(token, first, OperationFamily::GitHub, T0),
                Err(SurrogateError::Unknown),
                "a token for a revoked credential must not redeem"
            );
        }
        // The credential that was not revoked is untouched. A revocation that
        // took the whole table with it would be indistinguishable from a
        // denial of service against every other credential.
        assert_eq!(registry.len(), 1);
        assert_eq!(
            registry.redeem_for(&bystander_token, first, OperationFamily::GitHub, T0),
            Ok(bystander),
            "an unrelated credential's token must survive"
        );
    }

    /// Revocation is by credential and not by session, and the difference is
    /// the whole point: the agent holding a token when the operator revokes is
    /// the one that must lose it, and scoping to the revoking session would
    /// leave precisely that agent untouched.
    #[test]
    fn a_credential_revocation_crosses_sessions() {
        let doomed = credential();
        let holder = session();
        let mut registry = SurrogateRegistry::new();
        let (token, _, _) = registry
            .mint(holder, doomed, CredentialClass::Generic, 60, 5, T0)
            .expect("mint");

        // The "revoker" is a different session entirely, and still takes it.
        assert_eq!(registry.revoke_credential(doomed), 1);
        assert_eq!(
            registry.redeem_for(&token, holder, OperationFamily::GitHub, T0),
            Err(SurrogateError::Unknown)
        );
    }

    /// Revoking a credential nobody holds a token for is a no-op that says so,
    /// not a silent success and not a panic on an empty table.
    #[test]
    fn revoking_an_unheld_credential_removes_nothing() {
        let held = credential();
        let holder = session();
        let mut registry = SurrogateRegistry::new();
        let (token, _, _) = registry
            .mint(holder, held, CredentialClass::Generic, 60, 5, T0)
            .expect("mint");

        assert_eq!(registry.revoke_credential(credential()), 0);
        assert_eq!(registry.len(), 1, "the unrelated token is still there");
        // Redeemed under its *own* session, so this asserts the token still
        // works rather than the much weaker "it is not gone".
        assert_eq!(
            registry.redeem_for(&token, holder, OperationFamily::GitHub, T0),
            Ok(held),
            "an unrelated token must keep working"
        );
    }

    /// Ending a session must kill its surrogates. If tokens outlived the
    /// session, the session lifetime would not be a real boundary.
    #[test]
    fn ending_a_session_revokes_its_surrogates() {
        let doomed = session();
        let survivor = session();
        let mut registry = SurrogateRegistry::new();
        let (doomed_token, _) = {
            let (token, _, _) = registry
                .mint(doomed, credential(), CredentialClass::Generic, 60, 5, T0)
                .expect("mint");
            (token, ())
        };
        let (survivor_token, _, _) = registry
            .mint(survivor, credential(), CredentialClass::Generic, 60, 5, T0)
            .expect("mint");

        assert_eq!(registry.revoke_session(doomed), 1, "one token revoked");
        assert_eq!(registry.len(), 1, "the other session's token survives");
        assert_eq!(
            registry.redeem_for(&doomed_token, doomed, OperationFamily::GitHub, T0),
            Err(SurrogateError::Unknown)
        );
        assert!(registry
            .redeem_for(&survivor_token, survivor, OperationFamily::GitHub, T0)
            .is_ok());
    }

    /// Revoke is session-scoped, so one session cannot destroy another's token.
    /// Skipping this would turn a bug into a cross-session denial of service.
    #[test]
    fn one_session_cannot_revoke_another_sessions_token() {
        let owner = session();
        let mut registry = SurrogateRegistry::new();
        let (token, _, _) = registry
            .mint(owner, credential(), CredentialClass::Generic, 60, 5, T0)
            .expect("mint");

        assert!(
            !registry.revoke(&token, session()),
            "a stranger cannot revoke"
        );
        assert_eq!(registry.len(), 1, "the token is still there");
        assert!(
            registry
                .redeem_for(&token, owner, OperationFamily::GitHub, T0)
                .is_ok(),
            "and still works"
        );
        assert!(registry.revoke(&token, owner), "the owner can");
    }

    /// Sweeping keeps the table bounded without making lookup cost depend on
    /// unrelated garbage.
    #[test]
    fn sweeping_removes_only_expired_records() {
        let session = session();
        let mut registry = SurrogateRegistry::new();
        let (stale, _, _) = registry
            .mint(session, credential(), CredentialClass::Generic, 10, 5, T0)
            .expect("mint");
        let (fresh, _, _) = registry
            .mint(session, credential(), CredentialClass::Generic, 600, 5, T0)
            .expect("mint");

        assert_eq!(registry.sweep(T0 + 100), 1, "one record went");
        assert_eq!(registry.len(), 1);
        assert_eq!(
            registry.redeem_for(&stale, session, OperationFamily::GitHub, T0 + 100),
            Err(SurrogateError::Unknown)
        );
        assert!(registry
            .redeem_for(&fresh, session, OperationFamily::GitHub, T0 + 100)
            .is_ok());
    }

    /// A registry reports empty when nothing is live. UAT-030 asserts this
    /// after teardown, so the invariant is pinned here rather than only there.
    #[test]
    fn a_fresh_registry_is_empty() {
        let registry = SurrogateRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    /// The base64url encoder is written out, so its edge cases are pinned
    /// directly. A wrong length here would silently truncate entropy.
    #[test]
    fn base64url_encodes_without_padding_and_covers_both_pads() {
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(b"foob"), "Zm9vYg");
        assert_eq!(base64url(b"fooba"), "Zm9vYmE");
        assert_eq!(base64url(b"foobar"), "Zm9vYmFy");
        // 32 bytes, the surrogate width, must be exactly 43 unpadded chars.
        assert_eq!(base64url(&[0u8; 32]).len(), 43);
        // The two pad characters of the standard alphabet are replaced, so a
        // token never needs escaping in a header or a log line.
        assert!(!base64url(&[0xfb, 0xef, 0xbe]).contains('+'));
        assert!(!base64url(&[0xff, 0xff, 0xff]).contains('/'));
    }
}
