//! Whether the broker is running as the identity somebody installed it to be.
//!
//! # The residual this exists to close
//!
//! M7's first scope item — *dedicated broker UID production packaging* — is
//! undelivered, and the gate row says so in prose. Measured from the code, the
//! shape of the gap is this:
//!
//! * `main.rs` derives the socket path from the **running** uid, so the socket
//!   is already per-user;
//! * the socket is set to `0600` and its directory to `0700`, with the
//!   comment *"in dev this is the best available approximation"*;
//! * `harden::install` sets `PR_SET_DUMPABLE` to 0 and installs a Landlock
//!   ruleset and a seccomp deny-list.
//!
//! All of it is real, and **all of it lives inside the invoking user's own
//! boundary**. So any other program that user runs is in the same uid, is
//! outside `PR_SET_DUMPABLE`'s reach for the broker's `/proc/<pid>/mem`, and
//! can open the socket, the vault and the audit log. UAT-003 proves the broker
//! is unreadable by a process *lacking* `CAP_SYS_PTRACE`, which is a narrower
//! claim than "unreadable", and the difference between those two sentences is
//! exactly this uid.
//!
//! # Why a declaration rather than an inference
//!
//! The tempting version of this module asks whether the broker's uid "looks
//! like" a service account — below 1000, with no login shell, absent from the
//! invoking user's session. Every one of those is a heuristic, and this
//! repository has spent a cycle learning what a heuristic costs: it agrees
//! with the truth on the machine that wrote it and disagrees everywhere else,
//! with nothing failing when it does.
//!
//! So nothing here infers. The installation **declares** the uid the broker is
//! supposed to be, and the broker **measures** the uid it actually is, and the
//! answer is the comparison. That makes the property decidable, makes a
//! disagreement loud instead of silent, and makes the two outcomes that matter
//! separable:
//!
//! * a declaration that does **not** match is **always fatal**. An operator who
//!   declared `998` and got a broker running as their own account believes they
//!   have installed a service; the credential is in the wrong domain and
//!   nothing about the process says so. This is the "looks healthy while
//!   verifying nothing" shape the rest of the broker keeps refusing, in a new
//!   place.
//! * the **absence** of a declaration is not an error by itself — a developer
//!   running the broker on their own machine has no dedicated uid and should
//!   not have to invent one — but an installation that wants the guarantee can
//!   demand it, and then the absence is fatal too. That is what
//!   `--require-dedicated-identity` is for: without it, a packaged install can
//!   silently degrade into the development shape and still report success.
//!
//! # Real uid and effective uid
//!
//! Two syscalls, and the difference is not academic. The socket **path** is
//! derived from `getuid()` (the real uid) while the socket's `0600` ownership
//! is the **effective** uid. Under a setuid bit those disagree, and the
//! derivation is wrong in a way nothing else in the broker would notice. So
//! both are read, and a setuid broker is refused under the same demand that
//! refuses a missing declaration — it is not a posture anyone asked for.

/// What the installation declared, measured against what the process is.
///
/// Constructed by [`identity_verdict`] rather than by hand, so a caller cannot
/// assemble a verdict the function would not have reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityVerdict {
    /// No installation declared a uid.
    ///
    /// The broker therefore **cannot know** whether it shares an identity with
    /// the agent, and says so rather than guessing. This is every development
    /// run and every unpackaged deployment, and it is the honest reading rather
    /// than a placeholder: the socket is `0600` and the process is undumpable,
    /// both of which are real, and both of which stop meaning "private" at the
    /// boundary of the invoking user's own processes.
    ///
    /// The measured uid is carried rather than left implicit, because a report
    /// that had to supply it would supply *something* — and `0` is what a
    /// default would give, which reads as root and is the one value here that
    /// would be a lie rather than a simplification.
    Undeclared { uid: u32 },
    /// The declared uid is the one in force.
    Dedicated { uid: u32 },
    /// The installation declared one uid and the process is another.
    ///
    /// **Always fatal.** See the module docs: the operator believes they have
    /// a service, and the credential is in the wrong domain.
    Mismatch { declared: u32, actual: u32 },
}

/// The measured answer to "is this the identity that was installed?".
///
/// `declared` is what the launch contract said; `actual` is the uid the
/// process is running as. `None` for `declared` is not a default to be filled
/// in later — it is the ordinary development case and it has its own verdict,
/// because "nobody said" and "somebody said and was ignored" must never read
/// the same.
pub fn identity_verdict(actual: u32, declared: Option<u32>) -> IdentityVerdict {
    match declared {
        None => IdentityVerdict::Undeclared { uid: actual },
        Some(declared) if declared == actual => IdentityVerdict::Dedicated { uid: actual },
        Some(declared) => IdentityVerdict::Mismatch { declared, actual },
    }
}

/// Why a broker that was asked for a dedicated identity will not run.
///
/// Split from [`IdentityVerdict`] because the two have different severities: a
/// [`IdentityVerdict::Mismatch`] is fatal on its own, while
/// [`MissingDedicatedIdentity`] only exists when somebody asked for the
/// guarantee. An operator who never asked is not broken by their broker
/// declining to be one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingDedicatedIdentity {
    /// `--require-dedicated-identity` was given and nothing declared a uid.
    Undeclared,
    /// The same flag, and the process is setuid: its real and effective uids
    /// disagree, so the socket path derived from the real uid is not the path
    /// whose ownership the effective uid holds.
    Setuid { real: u32, effective: u32 },
}

/// What to do about a verdict, decided in one place.
///
/// `require_dedicated` is the operator asking for the guarantee. Returning a
/// verdict rather than an exit code keeps `main` a caller: the decision about
/// what counts as a usable identity belongs to this module, and a second
/// caller cannot reach a different conclusion from the same three numbers.
pub fn check(
    real_uid: u32,
    effective_uid: u32,
    declared: Option<u32>,
    require_dedicated: bool,
) -> Result<IdentityVerdict, BrokerIdentityError> {
    let verdict = identity_verdict(effective_uid, declared);
    if let IdentityVerdict::Mismatch { declared, actual } = verdict {
        return Err(BrokerIdentityError::DeclaredIdentityNotHonoured { declared, actual });
    }
    if require_dedicated {
        if real_uid != effective_uid {
            return Err(BrokerIdentityError::MissingDedicatedIdentity(
                MissingDedicatedIdentity::Setuid {
                    real: real_uid,
                    effective: effective_uid,
                },
            ));
        }
        if let IdentityVerdict::Undeclared { .. } = verdict {
            return Err(BrokerIdentityError::MissingDedicatedIdentity(
                MissingDedicatedIdentity::Undeclared,
            ));
        }
    }
    Ok(verdict)
}

impl IdentityVerdict {
    /// The measured `(uid, declared)` pair, for the wire.
    ///
    /// The verdict already carries both numbers, so this is a re-shaping rather
    /// than a second measurement — and it is kept as a method so that the
    /// report cannot be assembled from a *different* pair of numbers than the
    /// one the decision was made on. A caller that passed the real uid here and
    /// a declared uid from somewhere else would produce a report that disagrees
    /// with the refusal it just issued, which is the one thing this module
    /// exists to make impossible.
    pub fn as_measured(self) -> (u32, Option<u32>) {
        match self {
            IdentityVerdict::Undeclared { uid } => (uid, None),
            IdentityVerdict::Dedicated { uid } => (uid, Some(uid)),
            IdentityVerdict::Mismatch { declared, actual } => (actual, Some(declared)),
        }
    }
}

/// Why the broker refused to start over its own identity.
///
/// Rendered by `main` into the operator's terminal, so both variants say what
/// to do rather than only what went wrong. A refusal an operator cannot act on
/// is a refusal that gets worked around, and working around it puts the
/// credential back in the invoking user's domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerIdentityError {
    /// The installation declared a uid and the process is not it.
    DeclaredIdentityNotHonoured { declared: u32, actual: u32 },
    /// A dedicated identity was required and there is none.
    MissingDedicatedIdentity(MissingDedicatedIdentity),
}

impl BrokerIdentityError {
    /// The operator's terminal text, including the remedy.
    pub fn operator_message(&self) -> String {
        match self {
            Self::DeclaredIdentityNotHonoured { declared, actual } => format!(
                "the installation declared uid {declared} for this broker and this \
                 process is running as uid {actual}, so it is not the identity that \
                 was installed. Refusing to start: a broker holding a credential \
                 under an identity the operator did not choose is the case this \
                 flag exists to make visible. Start the broker as uid {declared}, \
                 or drop --identity-uid if this installation genuinely shares the \
                 invoking user's account."
            ),
            Self::MissingDedicatedIdentity(MissingDedicatedIdentity::Undeclared) => String::from(
                "--require-dedicated-identity was given and no --identity-uid \
                     declared one, so this broker cannot know whether it shares an \
                     account with the agent it is protecting. Refusing to start. \
                     Declare the uid with --identity-uid, or drop \
                     --require-dedicated-identity if sharing the account is \
                     acceptable here.",
            ),
            Self::MissingDedicatedIdentity(MissingDedicatedIdentity::Setuid {
                real,
                effective,
            }) => {
                format!(
                    "--require-dedicated-identity was given and this process is \
                     setuid: its real uid is {real} and its effective uid is \
                     {effective}. The socket path is derived from the real uid while \
                     the socket's 0600 ownership is the effective one, so the path \
                     and its owner disagree. Refusing to start: drop the setuid bit, \
                     or drop --require-dedicated-identity."
                )
            }
        }
    }
}

impl std::fmt::Display for BrokerIdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.operator_message())
    }
}

impl std::error::Error for BrokerIdentityError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// A declaration that is not honoured is refused with no flag involved.
    ///
    /// The two that matter most, because each is a case where the broker could
    /// have started and looked healthy.
    #[test]
    fn a_declared_uid_that_does_not_match_is_refused_whether_or_not_it_was_required() {
        for require in [false, true] {
            let refused = check(1000, 1000, Some(998), require);
            assert_eq!(
                refused,
                Err(BrokerIdentityError::DeclaredIdentityNotHonoured {
                    declared: 998,
                    actual: 1000
                }),
                "a broker running as 1000 under a declaration of 998 must not start, \
                 with require_dedicated={require}",
                require = require,
            );
        }
    }

    /// The absence of a declaration is the development case, not a fault.
    ///
    /// A developer on their own machine has no dedicated uid, and a module
    /// that refused them would be refused by the next person to run the tests.
    #[test]
    fn nobody_declared_an_identity_and_nobody_asked_for_one() {
        assert_eq!(
            check(1000, 1000, None, false),
            Ok(IdentityVerdict::Undeclared { uid: 1000 })
        );
    }

    /// …and it becomes a refusal the moment somebody asks for the guarantee.
    ///
    /// This is the half that matters for packaging: without it, a packaged
    /// install can omit the declaration, fall back to the development shape,
    /// and report success.
    #[test]
    fn a_required_identity_that_nobody_declared_is_refused() {
        assert_eq!(
            check(1000, 1000, None, true),
            Err(BrokerIdentityError::MissingDedicatedIdentity(
                MissingDedicatedIdentity::Undeclared
            ))
        );
    }

    /// The honest case: declared, matched, not setuid.
    #[test]
    fn a_declared_identity_that_is_honoured_is_dedicated() {
        assert_eq!(
            check(998, 998, Some(998), true),
            Ok(IdentityVerdict::Dedicated { uid: 998 })
        );
    }

    /// A matched declaration still runs when the guarantee was not demanded,
    /// because a deployment may declare its identity for the record without
    /// making it a condition of starting.
    #[test]
    fn a_matched_declaration_needs_no_flag_to_be_honoured() {
        assert_eq!(
            check(998, 998, Some(998), false),
            Ok(IdentityVerdict::Dedicated { uid: 998 })
        );
    }

    /// A setuid broker is refused **only** under the demand.
    ///
    /// The asymmetry is deliberate and is the reason the check is a function
    /// rather than three `if`s in `main`: a setuid broker whose identity is
    /// otherwise honoured and declared is a developer's own doing, and
    /// refusing it unconditionally would be a policy this product does not
    /// otherwise have. Under `--require-dedicated-identity` it is refused,
    /// because the socket path and the socket's owner disagree and nobody asked
    /// for that.
    #[test]
    fn a_setuid_broker_is_refused_only_when_a_dedicated_identity_was_required() {
        assert_eq!(
            check(1000, 998, Some(998), false),
            Ok(IdentityVerdict::Dedicated { uid: 998 }),
            "a setuid broker with a honoured declaration is not this product's \
             business unless somebody demanded a dedicated identity"
        );
        assert_eq!(
            check(1000, 998, Some(998), true),
            Err(BrokerIdentityError::MissingDedicatedIdentity(
                MissingDedicatedIdentity::Setuid {
                    real: 1000,
                    effective: 998
                }
            ))
        );
    }

    /// The verdict is decided by the comparison and nothing else.
    ///
    /// Three rows rather than one, because a verdict that could be assembled
    /// by hand from a different rule is a verdict two callers can disagree
    /// about.
    #[test]
    fn the_verdict_is_the_comparison() {
        assert_eq!(
            identity_verdict(1000, None),
            IdentityVerdict::Undeclared { uid: 1000 }
        );
        assert_eq!(
            identity_verdict(998, Some(998)),
            IdentityVerdict::Dedicated { uid: 998 }
        );
        assert_eq!(
            identity_verdict(1000, Some(998)),
            IdentityVerdict::Mismatch {
                declared: 998,
                actual: 1000
            }
        );
    }

    /// **A mismatch outranks everything else**, including the setuid check.
    ///
    /// Written as its own test because the ordering inside `check` is a
    /// decision rather than an accident: a setuid broker whose declaration is
    /// *also* wrong has two faults, and the one the operator can act on by
    /// changing which uid they run as is the one worth printing. Reordering the
    /// two checks would make this go red without anything else moving.
    #[test]
    fn a_mismatch_is_reported_in_preference_to_a_setuid_fault() {
        assert_eq!(
            check(1000, 2000, Some(998), true),
            Err(BrokerIdentityError::DeclaredIdentityNotHonoured {
                declared: 998,
                actual: 2000
            }),
            "the declaration is the fault the operator can act on directly"
        );
    }

    /// The report carries the same numbers the decision was made on.
    ///
    /// Its own test because this is where a lie would be *published* rather
    /// than merely written: the undeclared arm is the one that could quietly
    /// acquire a different uid, and `0` is what a default would give — which
    /// reads as root, the one answer here that inverts the meaning rather than
    /// approximating it.
    #[test]
    fn the_wire_carries_the_measured_uid_in_every_case() {
        assert_eq!(
            IdentityVerdict::Undeclared { uid: 1000 }.as_measured(),
            (1000, None),
            "an undeclared broker still runs as somebody; reporting 0 would be root"
        );
        assert_eq!(
            IdentityVerdict::Dedicated { uid: 998 }.as_measured(),
            (998, Some(998))
        );
        assert_eq!(
            IdentityVerdict::Mismatch {
                declared: 998,
                actual: 1000
            }
            .as_measured(),
            (1000, Some(998)),
            "a mismatch is unreachable on a running broker, and if one does reach \
             the report it must name both numbers rather than one"
        );
    }

    /// Every refusal names the remedy, because a refusal an operator cannot
    /// act on is a refusal that gets worked around.
    ///
    /// Substring checks rather than an equality against the whole sentence, so
    /// that rewording the message does not fail the test while *removing* the
    /// remedy does.
    #[test]
    fn every_refusal_says_what_to_do() {
        let refused = [
            BrokerIdentityError::DeclaredIdentityNotHonoured {
                declared: 998,
                actual: 1000,
            },
            BrokerIdentityError::MissingDedicatedIdentity(MissingDedicatedIdentity::Undeclared),
            BrokerIdentityError::MissingDedicatedIdentity(MissingDedicatedIdentity::Setuid {
                real: 1000,
                effective: 998,
            }),
        ];
        for error in refused {
            let text = error.operator_message();
            assert!(
                text.contains("--"),
                "the message names no flag to change: {text}"
            );
            assert!(
                text.len() > 80,
                "a refusal this short says what failed and not what to do: {text}"
            );
        }
    }
}
