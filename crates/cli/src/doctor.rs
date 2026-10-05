//! `asv doctor` — installation health, in a form a human and an agent can both
//! read.
//!
//! # The rule this module is built around
//!
//! `08-AAT-UAT.md` UAT-DX-004: *"No aceptar un booleano global `healthy` que
//! esconda la causa."* A single `healthy: false` sends an operator to the
//! source. What they need is which of eleven things is wrong, and what to do
//! about each.
//!
//! So the unit of report is a [`Check`] with an id, a state and a remedy, and
//! [`Status`](crate::agent::schema::Status) is *derived* from the set rather than reported beside it. Two
//! installations that are equally unusable produce the same `status` and
//! different `checks`, and the difference is the entire content of the
//! command. A consumer that only reads `status` still gets a correct coarse
//! answer; a consumer that reads `checks` gets the real one.
//!
//! # `unknown` is not `ok` and is not a failure
//!
//! Some facts are true only inside the broker — whether it has disabled
//! `PR_SET_DUMPABLE`, what product version it was built as. The CLI cannot ask:
//! the IPC surface has no field for either. Writing `true` would be a guess
//! and writing `false` would be a lie, so the value is [`TriState::Unknown`]
//! and the report carries a warning naming what could not be observed. An
//! unobservable fact does not degrade the status, because degrading on a
//! measurement nobody took would make `degraded` mean "this CLI is ignorant"
//! as often as it means "this installation is incomplete".

use crate::agent::schema::{Envelope, Status as EnvelopeStatus, Warning};
use crate::layout::{self, BrokerLookup, Layout};

use std::path::{Path, PathBuf};

/// One fact about the installation, and what to do about it when it is wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// Stable dotted id. The programmable part; `doctor --json` consumers and
    /// the human renderer both key on it.
    pub id: String,
    /// Short human name for the thing being checked.
    pub label: String,
    pub state: CheckState,
    /// What was observed, in one sentence. Never advice.
    pub detail: String,
    /// The next step, when there is one. A check with a failure and no remedy
    /// is a check that has made the operator work out the answer themselves,
    /// which is what `doctor` exists to stop.
    pub remedy: Option<String>,
}

/// How a check came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckState {
    Ok,
    /// Usable, with something optional missing. Degrades the status.
    Warn,
    /// Not usable. Blocks.
    Fail,
    /// Not observable from the CLI. Neither degrades nor blocks.
    Unknown,
    /// Observed, stated, and **not a defect in this installation**.
    ///
    /// Added for the broker's identity, and the reason is a mistake this
    /// increment would otherwise have shipped. A broker started by a
    /// developer's own shell shares that shell's uid, and that is the
    /// *documented* posture of an unpackaged deployment — the M7 gate row
    /// narrows its own claim to exactly this. Reporting it as `Warn` made every
    /// `asv doctor` on a development machine read `Degraded`, and a status that
    /// is permanently degraded is a status nobody reads, which is the same
    /// failure as a check that always passes.
    ///
    /// It is not `Unknown`, because it *is* observable and the number matters;
    /// it is not `Ok`, because `ok` next to a shared uid reads as a clean bill
    /// of health for the one property the broker cannot give itself. So it is
    /// its own state, carrying a remedy the operator can act on without being
    /// told their installation is broken.
    Info,
}

impl CheckState {
    /// The four spellings, shared by both renderers.
    pub fn as_str(self) -> &'static str {
        match self {
            CheckState::Ok => "ok",
            CheckState::Warn => "warn",
            CheckState::Fail => "fail",
            CheckState::Unknown => "unknown",
            CheckState::Info => "info",
        }
    }

    /// Every state, in severity order. The equivalence parser in
    /// `render::tests` recognises a check line by testing the first token
    /// against this, so it lives next to the spellings rather than being
    /// spelled out a second time over there.
    pub const ALL: [CheckState; 5] = [
        CheckState::Ok,
        CheckState::Warn,
        CheckState::Fail,
        CheckState::Unknown,
        CheckState::Info,
    ];
}

/// A fact that can be true, false, or not observable.
///
/// A `bool` here would be a lie in one direction or the other, which is the
/// whole subject of this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriState {
    Yes,
    No,
    Unknown,
}

impl TriState {
    pub fn as_str(self) -> &'static str {
        match self {
            TriState::Yes => "true",
            TriState::No => "false",
            TriState::Unknown => "unknown",
        }
    }

    fn observed(self) -> bool {
        !matches!(self, TriState::Unknown)
    }
}

/// What answering the socket did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketOutcome {
    /// Nothing answered.
    Unreachable { reason: String },
    /// Something answered `Pong` with this protocol version. The protocol's
    /// own `u16`, not a widened copy of it.
    Answered { protocol: u16 },
    /// Something answered, and what it said was not a `Pong`. A peer on the
    /// socket that is not this broker is worth distinguishing from a broker
    /// that is down: the first means "stale socket or another program", the
    /// second means "the service is not running".
    Unexpected { detail: String },
    /// A broker answered, and this is what it said about itself.
    ///
    /// DX1 reported `unknown` for the broker's version and its core-dump
    /// setting because `Ping` carries neither. DX2 widened the IPC for exactly
    /// those two facts, so this variant is what turns a guess into a
    /// measurement — and it is the only way to learn them, because the CLI
    /// reading `/proc/<pid>/status` would be reading a field another same-uid
    /// process can influence.
    SelfReported(Box<crate::ipc::BrokerFacts>),
}

impl SocketOutcome {
    /// The protocol version the peer reported, when it reported one.
    ///
    /// An accessor rather than a pattern match at each use site, because
    /// `SelfReported` and `Answered` are the same event seen at two
    /// resolutions: one is the liveness handshake, the other is that plus the
    /// broker's description. Treating them as two cases meant the protocol
    /// check had to learn about `SelfReported` separately, and a third way of
    /// learning about the broker would have needed it again.
    pub fn observed_protocol(&self) -> Option<u16> {
        match self {
            SocketOutcome::Answered { protocol } => Some(*protocol),
            SocketOutcome::SelfReported(facts) => Some(facts.protocol),
            SocketOutcome::Unreachable { .. } | SocketOutcome::Unexpected { .. } => None,
        }
    }

    /// Whether the peer is the broker, at either resolution.
    pub fn is_broker(&self) -> bool {
        self.observed_protocol().is_some()
    }
}

/// Kernel facilities the broker would use, as this kernel offers them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hardening {
    pub landlock: TriState,
    pub seccomp: TriState,
    /// Whether the *broker* disabled core dumps. Not observable from here.
    pub broker_dumpable: TriState,
}

/// Everything `doctor` looked at, with no judgement attached.
///
/// Split from [`DoctorReport`] so that the aggregation rules can be tested
/// against states that are awkward to produce for real — a broker answering
/// with the wrong protocol version, a kernel without Landlock — without
/// standing up a broker to produce them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub cli_version: String,
    pub socket: SocketOutcome,
    pub broker_lookup: BrokerLookup,
    pub config_dir: DirState,
    pub data_dir: DirState,
    pub vault: FileState,
    pub vault_unlockable: TriState,
    pub service_unit: FileState,
    /// Where the installed unit's `ExecStart` actually points, if it has one.
    pub unit_target: Option<PathBuf>,
    /// What the broker said about itself, when it was asked.
    pub broker_facts: Option<crate::ipc::BrokerFacts>,
    pub hardening: Hardening,
    pub channel: &'static str,
    pub managed_by: &'static str,
    /// Who placed these files, and how we know.
    pub origin: crate::installrecord::InstallationOrigin,
}

/// Whether a directory exists, and what mode it ended up with.
///
/// The judgement about whether the mode is acceptable belongs to `dir_check`,
/// not to the observation. Splitting them here would put the rule in two
/// places, and the two would be edited on different days.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirState {
    /// Exists, with this mode.
    Present {
        mode: u32,
    },
    Absent,
}

/// Whether a file exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileState {
    Present { mode: u32 },
    Absent,
}

/// The judgement. Checks plus the status derived from them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorReport {
    pub cli_version: String,
    pub socket: SocketOutcome,
    pub hardening: Hardening,
    pub installation_channel: &'static str,
    pub managed_by: &'static str,
    /// Who placed these files, and how we know. Carried through unchanged:
    /// `doctor` reports what it observed and the judgement is about the
    /// installation, not about who owns it.
    pub origin: crate::installrecord::InstallationOrigin,
    pub checks: Vec<Check>,
    pub warnings: Vec<Warning>,
}

impl DoctorReport {
    /// Runs the checks. Pure with respect to `obs`: everything it depends on
    /// has already been looked at.
    pub fn judge(obs: Observation) -> Self {
        let mut checks = Vec::new();
        let mut warnings = Vec::new();

        checks.push(Check {
            id: "cli.version".into(),
            label: "CLI version".into(),
            state: CheckState::Ok,
            detail: obs.cli_version.clone(),
            remedy: None,
        });

        // --- installation layout -----------------------------------------
        checks.push(dir_check(
            "install.config_dir",
            "Config directory",
            obs.config_dir,
            &obs.cli_version,
        ));
        checks.push(dir_check(
            "install.data_dir",
            "Vault directory",
            obs.data_dir,
            &obs.cli_version,
        ));

        checks.push(match &obs.broker_lookup {
            BrokerLookup::Found(p) => Check {
                id: "install.broker_binary".into(),
                label: "Private broker".into(),
                state: CheckState::Ok,
                detail: p.display().to_string(),
                remedy: None,
            },
            BrokerLookup::Refused { path, reason } => Check {
                id: "install.broker_binary".into(),
                label: "Private broker".into(),
                state: CheckState::Fail,
                detail: reason.explain(path),
                remedy: Some(
                    "install the agent-secretless bundle, or point ASV_LIBEXEC_DIR at the \
                     directory holding asv-brokerd"
                        .into(),
                ),
            },
        });

        checks.push(file_check(
            "install.service_unit",
            "systemd user unit",
            obs.service_unit,
            "asv setup writes the unit",
        ));

        // R8: after a mise upgrade the unit can still be pointing at the
        // previous installation, and the service starts happily from a path
        // that no longer holds the current build. Comparing what the unit says
        // against what this run resolved is the only way to see it, and the
        // unit being *present* says nothing about it being *right*.
        checks.push(match (&obs.unit_target, &obs.broker_lookup) {
            (Some(target), BrokerLookup::Found(resolved)) if target == resolved => Check {
                id: "install.unit_target".into(),
                label: "Unit target".into(),
                state: CheckState::Ok,
                detail: format!("ExecStart points at {}", resolved.display()),
                remedy: None,
            },
            (Some(target), _) => Check {
                id: "install.unit_target".into(),
                label: "Unit target".into(),
                state: CheckState::Fail,
                detail: format!(
                    "ExecStart runs {} but this installation resolved {}",
                    target.display(),
                    obs.broker_lookup.path().display()
                ),
                remedy: Some(
                    "run: asv setup, which rewrites ExecStart from the paths this \
                     installation resolved"
                        .into(),
                ),
            },
            (None, _) => Check {
                id: "install.unit_target".into(),
                label: "Unit target".into(),
                state: CheckState::Unknown,
                detail: "not checked: the unit has no ExecStart line".into(),
                remedy: None,
            },
        });

        // --- vault --------------------------------------------------------
        checks.push(match obs.vault {
            FileState::Present { mode } => Check {
                id: "vault.present".into(),
                label: "Vault file".into(),
                state: if mode & 0o077 == 0 {
                    CheckState::Ok
                } else {
                    CheckState::Fail
                },
                detail: format!("mode {mode:04o}"),
                remedy: if mode & 0o077 == 0 {
                    None
                } else {
                    Some(format!("chmod 600 {}", "the vault file"))
                },
            },
            FileState::Absent => Check {
                id: "vault.present".into(),
                label: "Vault file".into(),
                state: CheckState::Fail,
                detail: "no vault at the configured path".into(),
                remedy: Some("run: asv setup".into()),
            },
        });

        // The passphrase is checked by opening the vault, and the reason it
        // is a separate check is that it is the failure an operator cannot
        // self-diagnose: "the vault is there" and "the vault is usable" look
        // identical from the outside and have completely different fixes.
        checks.push(match obs.vault_unlockable {
            TriState::Yes => Check {
                id: "vault.unlockable".into(),
                label: "Vault opens".into(),
                state: CheckState::Ok,
                detail: "the stored passphrase unlocks the vault".into(),
                remedy: None,
            },
            TriState::No => Check {
                id: "vault.unlockable".into(),
                label: "Vault opens".into(),
                state: CheckState::Fail,
                detail: "the passphrase file does not unlock the vault".into(),
                // Deliberately no "regenerate it" here. The passphrase is the
                // only thing standing between the vault file and its
                // contents, and a tool that offers to replace it is a tool
                // that can destroy a credential store.
                remedy: Some(
                    "restore the correct passphrase, or restore a backup of the vault. \
                     asv will not overwrite either."
                        .into(),
                ),
            },
            TriState::Unknown => {
                warnings.push(Warning {
                    code: "VAULT_NOT_CHECKED".into(),
                    message: "the vault could not be opened, so its passphrase was not \
                              verified. This does not mean the passphrase is wrong."
                        .into(),
                });
                Check {
                    id: "vault.unlockable".into(),
                    label: "Vault opens".into(),
                    state: CheckState::Unknown,
                    detail: "not checked: the vault could not be read".into(),
                    remedy: None,
                }
            }
        });

        // --- the running broker -------------------------------------------
        //
        // Socket and protocol are separate checks, and this is the specific
        // thing UAT-DX-004 asks for. A stopped broker and an incompatible
        // broker are both `blocked`, and an earlier shape of this report gave
        // both of them the same line; the operator's next move differs — one
        // starts a service, the other upgrades a binary — and the single line
        // could not tell them which.
        checks.push(match &obs.socket {
            SocketOutcome::Unreachable { reason } => Check {
                id: "broker.socket".into(),
                label: "Broker socket".into(),
                state: CheckState::Fail,
                detail: reason.clone(),
                remedy: Some("run: systemctl --user start asv-brokerd".into()),
            },
            SocketOutcome::Unexpected { detail } => Check {
                id: "broker.socket".into(),
                label: "Broker socket".into(),
                state: CheckState::Fail,
                detail: format!("a peer answered that is not this broker: {detail}"),
                remedy: Some(
                    "remove the stale socket, or stop whatever else is bound to it".into(),
                ),
            },
            SocketOutcome::Answered { .. } => Check {
                id: "broker.socket".into(),
                label: "Broker socket".into(),
                state: CheckState::Ok,
                detail: "the broker answered".into(),
                remedy: None,
            },
            SocketOutcome::SelfReported(facts) => Check {
                id: "broker.socket".into(),
                label: "Broker socket".into(),
                state: CheckState::Ok,
                detail: format!(
                    "the broker answered, and reports itself as {}",
                    facts.product_version
                ),
                remedy: None,
            },
        });

        // **The one protection the broker cannot establish for itself.** Every
        // other fact in this report is something `main` set at startup; the
        // identity belongs to whoever launched the process, and a broker running
        // as the invoking user is inside that user's own boundary no matter how
        // undumpable it is. So it gets its own check with its own remedy, and
        // the three states stay three states: not measured is not the same as
        // measured-and-shared, and neither is the same as dedicated.
        checks.push(match &obs.socket {
            SocketOutcome::SelfReported(facts) => match facts.identity {
                None => Check {
                    id: "broker.identity".into(),
                    label: "Broker identity".into(),
                    // `Unknown`, which is what this is: this build does not
                    // report an identity. Not `Warn`, because an older broker
                    // is version skew and `broker.protocol` already says so.
                    state: CheckState::Unknown,
                    detail: "this broker did not report which uid it runs as".into(),
                    remedy: None,
                },
                Some(identity) if identity.dedicated => Check {
                    id: "broker.identity".into(),
                    label: "Broker identity".into(),
                    state: CheckState::Ok,
                    detail: format!(
                        "uid {}, and it is the identity the installation declared",
                        identity.uid
                    ),
                    remedy: None,
                },
                Some(identity) => Check {
                    id: "broker.identity".into(),
                    label: "Broker identity".into(),
                    // `Info`, and this is the state that earned its existence:
                    // a shared uid on an unpackaged deployment is what the
                    // product documents, not a fault in the installation.
                    state: CheckState::Info,
                    detail: match identity.declared_uid {
                        None => format!(
                            "uid {}, shared with the account that started it, and no \
                             installation declared an identity",
                            identity.uid
                        ),
                        Some(declared) => {
                            format!("uid {} running, with {} declared", identity.uid, declared)
                        }
                    },
                    // Naming the flag is the whole difference between a finding
                    // and a note: the operator cannot act on "not dedicated"
                    // and can act on this.
                    remedy: Some(
                        "every process running as this uid is outside the broker's \
                         hardening, because PR_SET_DUMPABLE only reaches other \
                         uids. Run the broker as a service account and declare it \
                         with --identity-uid, adding \
                         --require-dedicated-identity so a deployment that \
                         forgets cannot start."
                            .into(),
                    ),
                },
            },
            _ => Check {
                id: "broker.identity".into(),
                label: "Broker identity".into(),
                state: CheckState::Unknown,
                detail: "could not ask the broker which uid it runs as".into(),
                remedy: None,
            },
        });

        let protocol_compatible = match obs.socket.observed_protocol() {
            Some(protocol) => {
                if protocol == asv_ipc_protocol::PROTOCOL_VERSION {
                    Check {
                        id: "broker.protocol".into(),
                        label: "Protocol".into(),
                        state: CheckState::Ok,
                        detail: format!(
                            "broker speaks v{protocol}, this CLI speaks v{}",
                            asv_ipc_protocol::PROTOCOL_VERSION
                        ),
                        remedy: None,
                    }
                } else {
                    Check {
                        id: "broker.protocol".into(),
                        label: "Protocol".into(),
                        state: CheckState::Fail,
                        detail: format!(
                            "broker speaks v{protocol}, this CLI speaks v{}",
                            asv_ipc_protocol::PROTOCOL_VERSION
                        ),
                        // Naming the upgrade rather than "restart it" is the
                        // whole difference between this finding and the
                        // stopped-broker one above.
                        remedy: Some(
                            "the broker is an older or newer build than this CLI; \
                             upgrade the bundle so both come from the same release"
                                .into(),
                        ),
                    }
                }
            }
            _ => Check {
                id: "broker.protocol".into(),
                label: "Protocol".into(),
                state: CheckState::Unknown,
                detail: "not checked: no broker answered".into(),
                remedy: None,
            },
        };
        checks.push(protocol_compatible);

        // --- optional hardening -------------------------------------------
        //
        // Landlock and seccomp are warns, not fails. The broker runs without
        // them; what it loses is defence in depth, and a `doctor` that calls a
        // working installation `blocked` because the kernel lacks Landlock
        // trains its users to ignore it.
        checks.push(kernel_check(
            "hardening.landlock",
            "Landlock",
            obs.hardening.landlock,
            "sessions will run without a filesystem sandbox",
        ));
        checks.push(kernel_check(
            "hardening.seccomp",
            "seccomp",
            obs.hardening.seccomp,
            "the broker will run without a syscall filter",
        ));

        // Measured, since DX2 widened the IPC for it.
        checks.push(if let Some(facts) = &obs.broker_facts {
            Check {
                id: "broker.dumpable".into(),
                label: "Broker core dumps".into(),
                state: if facts.dumpable_disabled {
                    CheckState::Ok
                } else {
                    CheckState::Warn
                },
                detail: format!(
                    "the broker reports PR_SET_DUMPABLE={}",
                    if facts.dumpable_disabled { "0" } else { "1" }
                ),
                remedy: if facts.dumpable_disabled {
                    None
                } else {
                    Some(
                        "the broker is attached to a debugger. Start it with the harden \
                         profile, or find out why hardening was skipped."
                            .into(),
                    )
                },
            }
        } else if obs.hardening.broker_dumpable.observed() {
            Check {
                id: "broker.dumpable".into(),
                label: "Broker core dumps".into(),
                state: if obs.hardening.broker_dumpable == TriState::Yes {
                    CheckState::Ok
                } else {
                    CheckState::Warn
                },
                detail: format!("broker dumpable={}", obs.hardening.broker_dumpable.as_str()),
                remedy: None,
            }
        } else {
            warnings.push(Warning {
                code: "BROKER_HARDENING_UNOBSERVABLE".into(),
                message: "whether the broker disabled PR_SET_DUMPABLE cannot be read over \
                          the agent socket; the IPC handshake carries no such field"
                    .into(),
            });
            Check {
                id: "broker.dumpable".into(),
                label: "Broker core dumps".into(),
                state: CheckState::Unknown,
                detail: "not observable from the CLI".into(),
                remedy: None,
            }
        });

        // A warning only when the broker did not describe itself. Since DX2
        // the version is a measurement, so a document still claiming
        // "unobservable" is making a claim about the connection.
        if obs.broker_facts.is_none() {
            warnings.push(Warning {
                code: "BROKER_VERSION_UNOBSERVABLE".into(),
                message: "the broker did not describe itself, so `broker_version` is \
                          reported as null rather than assumed equal to the CLI's"
                    .into(),
            });
        }

        // An install record that exists and cannot be read is the one case
        // worth a warning: the installation was placed by something, and the
        // owner is now unknown. `installed_via` still reports `source` so the
        // field is never absent, but `installed_via_source: unreadable` is
        // what stops a reader treating that as a finding — and it is what
        // stops an update path from deciding it owns these files.
        if obs.origin.provenance == crate::installrecord::Provenance::Unreadable {
            warnings.push(Warning {
                code: "INSTALL_RECORD_UNREADABLE".into(),
                message: format!(
                    "an install record exists but could not be read, so the owner of \
                     this installation is unknown. Do not treat these files as \
                     unowned: {}",
                    obs.origin.reason.as_deref().unwrap_or("no reason recorded")
                ),
            });
        }

        Self {
            cli_version: obs.cli_version,
            socket: obs.socket,
            hardening: obs.hardening,
            installation_channel: obs.channel,
            managed_by: obs.managed_by,
            origin: obs.origin,
            checks,
            warnings,
        }
    }

    /// The coarse answer, derived. Never read instead of `checks`; read when
    /// the caller only needs to know whether to proceed.
    pub fn status(&self) -> EnvelopeStatus {
        if self.checks.iter().any(|c| c.state == CheckState::Fail) {
            EnvelopeStatus::Blocked
        } else if self.checks.iter().any(|c| c.state == CheckState::Warn) {
            EnvelopeStatus::Degraded
        } else {
            EnvelopeStatus::Ready
        }
    }

    /// The ids of the checks that are blocking, in report order.
    ///
    /// Exposed because the coarse `status` deliberately loses this, and the
    /// test for UAT-DX-004 compares it between two installations that are both
    /// `blocked`.
    pub fn blocking(&self) -> Vec<&str> {
        self.checks
            .iter()
            .filter(|c| c.state == CheckState::Fail)
            .map(|c| c.id.as_str())
            .collect()
    }

    pub fn check(&self, id: &str) -> Option<&Check> {
        self.checks.iter().find(|c| c.id == id)
    }

    /// The `asv.agent/v1` document, with the fields `06-CLI-CONTRACT.md` §7
    /// names plus the per-check breakdown the same UAT requires.
    pub fn to_envelope(&self) -> Envelope {
        let protocol_compatible = self
            .check("broker.protocol")
            .map(|c| c.state == CheckState::Ok || c.state == CheckState::Warn);
        let socket_reachable = matches!(
            self.socket,
            SocketOutcome::Answered { .. } | SocketOutcome::SelfReported { .. }
        );

        let data = serde_json::json!({
            "cli_version": self.cli_version,
            // A measurement since DX2, a sentence when there was none, and
            // never the CLI's own version — that was the guess this replaced.
            "broker_version": match &self.socket {
                SocketOutcome::SelfReported(facts) => {
                    serde_json::Value::String(facts.product_version.clone())
                }
                _ => serde_json::Value::String(
                    "unknown: the broker did not describe itself".into(),
                ),
            },
            "protocol_compatible": protocol_compatible,
            "socket": { "reachable": socket_reachable },
            // The identity beside the hardening rather than inside it,
            // because it is not something `main` established. Measured, never
            // inferred: `not_measured` is a distinct answer from `not
            // dedicated`, and merging them is how a diagnostic ends up
            // reassuring.
            "identity": match &self.socket {
                SocketOutcome::SelfReported(facts) => match facts.identity {
                    None => serde_json::json!({ "state": "not_measured" }),
                    Some(identity) => serde_json::json!({
                        "state": if identity.dedicated { "dedicated" } else { "shared" },
                        "uid": identity.uid,
                        "declared_uid": identity.declared_uid,
                    }),
                },
                _ => serde_json::json!({ "state": "not_measured" }),
            },
            "hardening": {
                "dumpable_disabled": match &self.socket {
                    SocketOutcome::SelfReported(facts) => {
                        serde_json::Value::String(
                            if facts.dumpable_disabled { "true" } else { "false" }.into(),
                        )
                    }
                    _ => serde_json::Value::String(self.hardening.broker_dumpable.as_str().into()),
                },
                "no_new_privs": match &self.socket {
                    SocketOutcome::SelfReported(facts) => {
                        serde_json::Value::String(
                            if facts.no_new_privs { "true" } else { "false" }.into(),
                        )
                    }
                    _ => serde_json::Value::String("unknown".into()),
                },
                "landlock": self.hardening.landlock.as_str(),
                "seccomp": self.hardening.seccomp.as_str(),
            },
            "installation": {
                "channel": self.installation_channel,
                "managed_by": self.managed_by,
                // DX4. `installed_via` is the field the ADR asks for, and it
                // ships with its provenance because a value read from a file
                // and a value guessed from a path are not the same claim.
                // `channel` above is still the path heuristic; this is the
                // record, and when the record is unreadable that is said
                // rather than papered over with `source`.
                "installed_via": self.origin.installed_via.as_str(),
                "installed_via_source": self.origin.provenance.as_str(),
                "installed_via_owns_updates": self.origin.installed_via.owns_updates(),
                "install_version": self.origin.record.as_ref().map(|r| r.version.as_str()),
                "install_root": self.origin.record.as_ref().map(|r| r.install_root.display().to_string()),
                "update_via": self.origin.installed_via.update_hint(),
            },
            "checks": self.checks.iter().map(|c| serde_json::json!({
                "id": c.id,
                "label": c.label,
                "state": c.state.as_str(),
                "detail": c.detail,
                "remedy": c.remedy,
            })).collect::<Vec<_>>(),
            "blocking": self.blocking(),
        });

        let mut envelope = Envelope::new(self.status(), data);
        for warning in &self.warnings {
            envelope = envelope.with_warning(&warning.code, warning.message.clone());
        }
        // A stopped broker publishes only `doctor` and `setup`. See
        // `AgentRel::publishable_for`.
        for rel in crate::agent::relations::AgentRel::publishable_for(socket_reachable) {
            envelope = envelope.with_link(rel.descriptor());
        }
        envelope
    }
}

fn dir_check(id: &str, label: &str, state: DirState, _cli_version: &str) -> Check {
    match state {
        DirState::Present { mode } if mode & 0o077 == 0 => Check {
            id: id.into(),
            label: label.into(),
            state: CheckState::Ok,
            detail: format!("present, mode {mode:04o}"),
            remedy: None,
        },
        DirState::Present { mode } => Check {
            id: id.into(),
            label: label.into(),
            state: CheckState::Fail,
            detail: format!("present, mode {mode:04o} — readable by other users"),
            remedy: Some("run: chmod 700 the directory".into()),
        },
        DirState::Absent => Check {
            id: id.into(),
            label: label.into(),
            state: CheckState::Fail,
            detail: "not created".into(),
            remedy: Some("run: asv setup".into()),
        },
    }
}

fn file_check(id: &str, label: &str, state: FileState, remedy: &str) -> Check {
    match state {
        FileState::Present { mode } => Check {
            id: id.into(),
            label: label.into(),
            state: CheckState::Ok,
            detail: format!("installed, mode {mode:04o}"),
            remedy: None,
        },
        FileState::Absent => Check {
            id: id.into(),
            label: label.into(),
            state: CheckState::Fail,
            detail: "not installed".into(),
            remedy: Some(remedy.into()),
        },
    }
}

fn kernel_check(id: &str, label: &str, state: TriState, consequence: &str) -> Check {
    match state {
        TriState::Yes => Check {
            id: id.into(),
            label: label.into(),
            state: CheckState::Ok,
            detail: "available".into(),
            remedy: None,
        },
        TriState::No => Check {
            id: id.into(),
            label: label.into(),
            state: CheckState::Warn,
            detail: format!("unavailable — {consequence}"),
            remedy: None,
        },
        TriState::Unknown => Check {
            id: id.into(),
            label: label.into(),
            state: CheckState::Unknown,
            detail: "could not be determined on this kernel".into(),
            remedy: None,
        },
    }
}

// --- observing -----------------------------------------------------------

impl Observation {
    /// Looks at the real installation.
    pub fn gather(layout: &Layout) -> Self {
        let socket_path = layout
            .socket_override
            .clone()
            .unwrap_or_else(crate::default_socket);
        let mut socket = crate::observe_broker_socket_at(&socket_path);
        let broker_facts = match &socket {
            SocketOutcome::Answered { .. } => crate::ipc::fetch_broker_facts(&socket_path),
            _ => None,
        };
        if let Some(facts) = &broker_facts {
            socket = SocketOutcome::SelfReported(Box::new(facts.clone()));
        }
        let vault = file_state(&layout.vault);
        let vault_unlockable = match vault {
            FileState::Present { .. } => unlockable(layout),
            FileState::Absent => TriState::Unknown,
        };

        Self {
            cli_version: crate::build_version().to_string(),
            socket,
            broker_facts,
            broker_lookup: layout::lookup_broker_binary(),
            config_dir: dir_state(&layout.config_dir),
            data_dir: dir_state(&layout.data_dir),
            vault,
            vault_unlockable,
            service_unit: file_state(&layout.unit),
            unit_target: unit_exec_start_binary(&layout.unit),
            hardening: detect_hardening(),
            channel: detect_channel(),
            managed_by: detect_managed_by(),
            origin: crate::installrecord::origin(),
        }
    }
}

fn dir_state(path: &Path) -> DirState {
    match layout::mode_of(path) {
        Some(mode) => DirState::Present { mode },
        None => DirState::Absent,
    }
}

/// The binary the installed unit will run, read out of the file on disk.
///
/// Parsed rather than assumed. The assumption is exactly what R8 is about:
/// a unit that exists is not a unit that points at this installation.
fn unit_exec_start_binary(unit: &Path) -> Option<PathBuf> {
    let text = std::fs::read_to_string(unit).ok()?;
    let line = text.lines().find(|l| l.starts_with("ExecStart="))?;
    // `ExecStart=/path/to/binary arg arg`. The binary is the first
    // whitespace-separated token, and a template's `%h/...` expands to the
    // user's home — so a unit still carrying specifiers is reported as the
    // specifier, which is the state worth noticing after a layout change.
    let rest = line.strip_prefix("ExecStart=")?.trim_start();
    let binary = rest.split_whitespace().next()?;
    if binary.is_empty() {
        return None;
    }
    Some(PathBuf::from(binary))
}

fn file_state(path: &Path) -> FileState {
    match layout::mode_of(path) {
        Some(mode) => FileState::Present { mode },
        None => FileState::Absent,
    }
}

/// Opens the vault with the stored passphrase.
///
/// Returns `Unknown` rather than `No` when the passphrase file is missing: the
/// vault may well be fine, and reporting a bad passphrase when the file is
/// simply not there would send the operator to restore something that was
/// never lost.
fn unlockable(layout: &Layout) -> TriState {
    let Ok(bytes) = std::fs::read(&layout.passphrase) else {
        return TriState::Unknown;
    };
    let text = String::from_utf8_lossy(&bytes);
    let passphrase = text.trim_end_matches(['\n', '\r']);
    if passphrase.is_empty() {
        return TriState::Unknown;
    }
    let secret = secrecy::SecretString::from(passphrase.to_string());
    match asv_vault::VaultStore::open(&layout.vault, &secret) {
        Ok(_) => TriState::Yes,
        Err(_) => TriState::No,
    }
}

/// Asks the kernel what it offers, rather than what this build was compiled
/// against.
///
/// The difference matters: Landlock and seccomp are both "available" as crate
/// features, and neither means the running kernel will accept the syscall. A
/// `doctor` built on `cfg` would report `available` on a kernel from 2019.
pub fn detect_hardening() -> Hardening {
    Hardening {
        landlock: probe_landlock(),
        seccomp: probe_seccomp(),
        // Not observable from here. See the report's warnings.
        broker_dumpable: TriState::Unknown,
    }
}

/// `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` returns
/// the ABI version, or `ENOSYS` on a kernel without it. A raw syscall rather
/// than a libc wrapper, because the point is to ask the kernel and the libc
/// this build links may predate the syscall entirely.
fn probe_landlock() -> TriState {
    // `__NR_landlock_create_ruleset` is 444 on every architecture Linux
    // currently ships, but the syscall number is looked up where the libc
    // headers declare it so that a wrong constant cannot be mistaken for an
    // absent feature.
    const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
    // LANDLOCK_CREATE_RULESET_VERSION
    const VERSION_FLAG: u32 = 1;

    let ret = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<libc::c_void>(),
            0usize,
            VERSION_FLAG,
        )
    };
    if ret > 0 {
        TriState::Yes
    } else {
        TriState::No
    }
}

/// `/proc/sys/kernel/seccomp/actions_avail` is present when CONFIG_SECCOMP is
/// on. Reading the file is the observation; the process's own filter is a
/// different question and would need a `prctl` round trip that could itself be
/// refused.
fn probe_seccomp() -> TriState {
    if std::path::Path::new("/proc/sys/kernel/seccomp/actions_avail").exists() {
        TriState::Yes
    } else {
        TriState::No
    }
}

/// Which channel put this `asv` here.
///
/// This is the question an operator asks when a release behaves differently
/// than expected, and answering it wrongly is worse than not answering: a
/// `cargo install` build reporting `mise` sends somebody to delete a mise
/// plugin that was never involved.
pub fn detect_channel() -> &'static str {
    let Ok(exe) = std::env::current_exe() else {
        return "unknown";
    };
    let text = exe.to_string_lossy();
    if text.contains("/.local/share/mise/") || text.contains("/.asv/") {
        "mise"
    } else if text.contains("/.local/bin/") {
        "shell-installer"
    } else {
        "source"
    }
}

/// What put this `asv` here — the difference between a user running the
/// installer and a package manager having done it.
pub fn detect_managed_by() -> &'static str {
    if std::env::var_os("ASV_INSTALLER").is_some() {
        "installer"
    } else {
        "direct"
    }
}

#[cfg(test)]
mod tests;
