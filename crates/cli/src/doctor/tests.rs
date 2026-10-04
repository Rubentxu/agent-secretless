//! `asv doctor` — UAT-DX-004 and the aggregation rules.
//!
//! The tests here are arranged around one question from UAT-DX-004: *"No
//! aceptar un booleano global `healthy` que esconda la causa."* A stopped
//! broker and an incompatible broker are both unusable, so a report built
//! around a single boolean renders them identically and the operator has no
//! way to tell that one needs `systemctl start` and the other needs an
//! upgrade. Every test below is about keeping those two apart.

use super::*;

use crate::layout::Refusal;
use std::io::Write;

/// A complete, healthy-by-construction observation. Each test moves exactly
/// one field away from this, so a failure names the field that mattered.
fn healthy() -> Observation {
    Observation {
        cli_version: "0.26.0".into(),
        socket: SocketOutcome::Answered {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION,
        },
        broker_lookup: BrokerLookup::Found("/home/u/.local/libexec/asv/asv-brokerd".into()),
        config_dir: DirState::Present { mode: 0o700 },
        data_dir: DirState::Present { mode: 0o700 },
        vault: FileState::Present { mode: 0o600 },
        vault_unlockable: TriState::Yes,
        service_unit: FileState::Present { mode: 0o644 },
        unit_target: Some("/home/u/.local/libexec/asv/asv-brokerd".into()),
        broker_facts: None,
        hardening: Hardening {
            landlock: TriState::Yes,
            seccomp: TriState::Yes,
            broker_dumpable: TriState::Unknown,
        },
        channel: "stable",
        managed_by: "direct",
        origin: crate::installrecord::InstallationOrigin::source_without_record(),
    }
}

// --- UAT-DX-004 ---------------------------------------------------------

/// The headline case.
///
/// Both installations are `blocked`. If the report is only the status, they
/// are the same report, and the operator is left to guess which of the two
/// very different fixes applies. The assertion is on the *blocking set* and
/// on the remedy text, because those are what an operator acts on.
#[test]
fn a_stopped_broker_and_an_incompatible_broker_are_different_findings() {
    let stopped = DoctorReport::judge(Observation {
        socket: SocketOutcome::Unreachable {
            reason: "no answer at /run/user/1000/asv/broker.sock".into(),
        },
        ..healthy()
    });
    let incompatible = DoctorReport::judge(Observation {
        socket: SocketOutcome::Answered {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION.wrapping_add(7),
        },
        ..healthy()
    });

    // Both unusable. That much they agree on.
    assert_eq!(stopped.status(), EnvelopeStatus::Blocked);
    assert_eq!(incompatible.status(), EnvelopeStatus::Blocked);

    // And here is where they have to part company.
    assert_eq!(
        stopped.blocking(),
        vec!["broker.socket"],
        "a stopped broker should name the socket"
    );
    assert_eq!(
        incompatible.blocking(),
        vec!["broker.protocol"],
        "an incompatible broker is reachable; blaming the socket sends the \
         operator to start a service that is already running"
    );

    let stopped_fix = stopped
        .check("broker.socket")
        .unwrap()
        .remedy
        .clone()
        .unwrap();
    let incompatible_fix = incompatible
        .check("broker.protocol")
        .unwrap()
        .remedy
        .clone()
        .unwrap();
    assert_ne!(
        stopped_fix, incompatible_fix,
        "the two findings ship the same advice, which is the boolean's failure \
         in prose"
    );
    assert!(
        stopped_fix.contains("start"),
        "the stopped broker's fix should mention starting: {stopped_fix}"
    );
    assert!(
        incompatible_fix.contains("upgrade"),
        "the incompatible broker's fix should mention upgrading: {incompatible_fix}"
    );
}

/// A peer that answers with something that is not a `Pong` is a third state,
/// not a second spelling of the first. A stale socket left behind by a broker
/// that was killed, or another program bound to the path, produces this — and
/// "start the service" is exactly wrong for it, because the socket is already
/// occupied.
#[test]
fn something_that_is_not_the_broker_is_not_the_same_as_no_answer() {
    let report = DoctorReport::judge(Observation {
        socket: SocketOutcome::Unexpected {
            detail: "a SessionCreated answered instead".into(),
        },
        ..healthy()
    });

    assert_eq!(report.blocking(), vec!["broker.socket"]);
    let remedy = report
        .check("broker.socket")
        .unwrap()
        .remedy
        .clone()
        .unwrap();
    assert!(
        remedy.contains("stale") || remedy.contains("bound"),
        "the fix for an occupied socket should name the occupancy: {remedy}"
    );
}

/// The third state UAT-DX-004 names: hardening absent. It degrades and does
/// not block, because the product works without it.
#[test]
fn missing_optional_hardening_degrades_rather_than_blocks() {
    let report = DoctorReport::judge(Observation {
        hardening: Hardening {
            landlock: TriState::No,
            seccomp: TriState::No,
            broker_dumpable: TriState::Unknown,
        },
        ..healthy()
    });

    assert_eq!(report.status(), EnvelopeStatus::Degraded);
    assert!(report.blocking().is_empty());
    assert_eq!(
        report.check("hardening.landlock").unwrap().state,
        CheckState::Warn
    );
    assert_eq!(
        report.check("hardening.seccomp").unwrap().state,
        CheckState::Warn
    );
}

// --- aggregation ---------------------------------------------------------

/// The whole aggregation table, in one place, so that adding a check has to
/// be thought about against these rows.
#[test]
fn the_status_is_derived_and_only_derived() {
    let cases: Vec<(&str, Observation, EnvelopeStatus)> = vec![
        ("everything in place", healthy(), EnvelopeStatus::Ready),
        (
            "one warning",
            Observation {
                hardening: Hardening {
                    landlock: TriState::No,
                    seccomp: TriState::Yes,
                    broker_dumpable: TriState::Unknown,
                },
                ..healthy()
            },
            EnvelopeStatus::Degraded,
        ),
        (
            "one failure, several warnings",
            Observation {
                socket: SocketOutcome::Unreachable {
                    reason: "refused".into(),
                },
                hardening: Hardening {
                    landlock: TriState::No,
                    seccomp: TriState::No,
                    broker_dumpable: TriState::Unknown,
                },
                ..healthy()
            },
            EnvelopeStatus::Blocked,
        ),
    ];

    for (label, obs, expected) in cases {
        let report = DoctorReport::judge(obs);
        assert_eq!(report.status(), expected, "{label}");
    }
}

/// `unknown` is neither of the other two. A fact nobody measured is not a
/// finding, and treating it as one would make `degraded` mean "this CLI is
/// ignorant" about as often as it means "this installation is incomplete".
///
/// `broker_dumpable` is `Unknown` in the healthy fixture, and the healthy
/// fixture is `ready` — this is the assertion that those two hold together.
#[test]
fn an_unobservable_fact_does_not_change_the_status() {
    let report = DoctorReport::judge(healthy());
    assert_eq!(
        report.check("broker.dumpable").unwrap().state,
        CheckState::Unknown
    );
    assert_eq!(report.status(), EnvelopeStatus::Ready);

    // And it is said out loud, not left to be inferred from a missing field.
    let codes: Vec<&str> = report.warnings.iter().map(|w| w.code.as_str()).collect();
    assert!(
        codes.contains(&"BROKER_HARDENING_UNOBSERVABLE"),
        "an unobservable fact was not reported as a warning: {codes:?}"
    );
}

/// Every warning code the report emits is one a consumer can branch on.
/// A code that is a sentence is a code nobody can match.
#[test]
fn every_warning_code_is_a_stable_identifier() {
    let report = DoctorReport::judge(Observation {
        hardening: Hardening {
            landlock: TriState::No,
            seccomp: TriState::No,
            broker_dumpable: TriState::Unknown,
        },
        ..healthy()
    });
    assert!(
        !report.warnings.is_empty(),
        "the control: warnings exist here"
    );
    for w in &report.warnings {
        assert!(
            w.code
                .chars()
                .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit()),
            "`{}` is not a screaming-snake identifier",
            w.code
        );
    }
}

/// A vault directory another user can read is a finding, not a cosmetic
/// difference. The vault file inside it is 0600, but the directory is what
/// decides whether the file can be replaced, and a replaceable vault is a
/// vault the broker will happily open.
#[test]
fn a_world_readable_vault_directory_is_a_failure() {
    let report = DoctorReport::judge(Observation {
        data_dir: DirState::Present { mode: 0o755 },
        ..healthy()
    });
    assert_eq!(report.status(), EnvelopeStatus::Blocked);
    assert_eq!(report.blocking(), vec!["install.data_dir"]);
    assert!(report.check("install.data_dir").unwrap().remedy.is_some());
}

/// The broker binary is `required-private` in the manifest. An installation
/// without it cannot start, and the remedy has to be "install the bundle",
/// not "reinstall the CLI" — the CLI is present, which is why the command ran.
#[test]
fn a_missing_private_broker_blocks_with_the_bundle_as_the_remedy() {
    let report = DoctorReport::judge(Observation {
        broker_lookup: BrokerLookup::Refused {
            path: "/usr/libexec/asv/asv-brokerd".into(),
            reason: Refusal::NotFound,
        },
        ..healthy()
    });
    let check = report.check("install.broker_binary").unwrap();
    assert_eq!(check.state, CheckState::Fail);
    assert!(
        check.remedy.as_ref().unwrap().contains("bundle"),
        "the fix should name the bundle: {:?}",
        check.remedy
    );
}

// --- the JSON ------------------------------------------------------------

/// UAT-DX-004's prohibition, checked against the document rather than against
/// the source: a consumer that finds `healthy` here will use it.
#[test]
fn the_json_carries_no_global_health_boolean() {
    let report = DoctorReport::judge(Observation {
        socket: SocketOutcome::Unreachable {
            reason: "refused".into(),
        },
        ..healthy()
    });
    let value: serde_json::Value =
        serde_json::from_str(&report.to_envelope().to_json()).expect("round-trips");

    assert!(
        value["data"].get("healthy").is_none(),
        "a global `healthy` is exactly what UAT-DX-004 forbids: {value}"
    );
    assert!(
        value["data"]["checks"].as_array().unwrap().len() > 5,
        "the per-check breakdown is the replacement; it is not there"
    );
    assert!(!value["data"]["blocking"].as_array().unwrap().is_empty());
}

/// The contract's fixed keys are present even when the answer is bad.
#[test]
fn the_contract_fields_are_present_in_every_state() {
    for obs in [
        healthy(),
        Observation {
            socket: SocketOutcome::Unreachable { reason: "x".into() },
            ..healthy()
        },
    ] {
        let value: serde_json::Value =
            serde_json::from_str(&DoctorReport::judge(obs).to_envelope().to_json()).unwrap();
        for key in [
            "cli_version",
            "broker_version",
            "protocol_compatible",
            "socket",
            "hardening",
            "installation",
        ] {
            assert!(value["data"].get(key).is_some(), "`{key}` missing");
        }
    }
}

/// `broker_version` is never a copy of the CLI's own version.
///
/// An earlier shape of this report filled it in, on the reasoning that a
/// broker and a CLI from the same bundle are the same build. That is usually
/// true and is not a fact.
///
/// DX1 could only report `null`, because `Ping` carries a protocol number and
/// nothing else. DX2 widened the IPC, so there is now a real value to report
/// when the broker describes itself — and a sentence saying it did not when it
/// did not. The property this test guards is the one that survived both: the
/// field is never the CLI's version guessed at it.
#[test]
fn the_broker_version_is_never_the_clis_own() {
    let cli_version = env!("CARGO_PKG_VERSION");

    // No broker facts: says so, rather than guessing.
    let value: serde_json::Value =
        serde_json::from_str(&DoctorReport::judge(healthy()).to_envelope().to_json()).unwrap();
    let reported = value["data"]["broker_version"].as_str().unwrap();
    assert_ne!(
        reported, cli_version,
        "the broker's version was filled in with the CLI's"
    );
    assert!(
        reported.contains("unknown"),
        "an unobserved version should say so, not read like a version: {reported}"
    );

    // With broker facts: the measured value, which is a different string from
    // the CLI's even when both builds are the same version.
    let facts = crate::ipc::BrokerFacts {
        protocol: asv_ipc_protocol::PROTOCOL_VERSION,
        product_version: "0.26.0-broker".into(),
        dumpable_disabled: true,
        no_new_privs: true,
        landlock_installed: true,
        seccomp_installed: true,
        capabilities: vec!["system.health".into()],
        connect_listen: None,
        identity: Some(asv_ipc_protocol::BrokerIdentity::measured(1000, None)),
    };
    let measured = DoctorReport::judge(Observation {
        socket: SocketOutcome::SelfReported(Box::new(facts)),
        broker_facts: None,
        ..healthy()
    });
    let value: serde_json::Value = serde_json::from_str(&measured.to_envelope().to_json()).unwrap();
    assert_eq!(value["data"]["broker_version"], "0.26.0-broker");
}

/// The core-dump setting is a measurement now, not a shrug.
#[test]
fn a_broker_that_describes_itself_gets_a_measured_dumpable_check() {
    let facts = crate::ipc::BrokerFacts {
        protocol: asv_ipc_protocol::PROTOCOL_VERSION,
        product_version: "0.26.0".into(),
        dumpable_disabled: true,
        no_new_privs: true,
        landlock_installed: true,
        seccomp_installed: true,
        capabilities: vec![],
        identity: Some(asv_ipc_protocol::BrokerIdentity::measured(1000, None)),
        connect_listen: None,
    };
    let report = DoctorReport::judge(Observation {
        socket: SocketOutcome::SelfReported(Box::new(facts.clone())),
        broker_facts: Some(facts),
        ..healthy()
    });

    let check = report.check("broker.dumpable").unwrap();
    assert_eq!(
        check.state,
        CheckState::Ok,
        "a broker that reported PR_SET_DUMPABLE=0 is reported as unknown"
    );
    assert!(
        check.detail.contains("PR_SET_DUMPABLE=0"),
        "{}",
        check.detail
    );

    let codes: Vec<&str> = report.warnings.iter().map(|w| w.code.as_str()).collect();
    assert!(
        !codes.contains(&"BROKER_HARDENING_UNOBSERVABLE"),
        "the warning fired for a fact that was measured: {codes:?}"
    );
    assert!(
        !codes.contains(&"BROKER_VERSION_UNOBSERVABLE"),
        "the version warning fired for a broker that described itself: {codes:?}"
    );
}

/// A broker that reports `PR_SET_DUMPABLE=1` is a finding, not a shrug.
///
/// The fail-closed direction: the previous default could not produce this
/// case at all, because it had no way to learn it.
#[test]
fn a_debuggable_broker_is_a_warning_with_a_remedy() {
    let facts = crate::ipc::BrokerFacts {
        protocol: asv_ipc_protocol::PROTOCOL_VERSION,
        product_version: "0.26.0".into(),
        dumpable_disabled: false,
        no_new_privs: false,
        landlock_installed: false,
        seccomp_installed: false,
        capabilities: vec![],
        // This broker is unhardened in every other way too, so its identity is
        // also unmeasured. That is the honest pairing: a broker from a build
        // with no identity check cannot report one, and claiming it could
        // would be the invention this field exists to prevent.
        identity: None,
        connect_listen: None,
    };
    let report = DoctorReport::judge(Observation {
        socket: SocketOutcome::SelfReported(Box::new(facts.clone())),
        broker_facts: Some(facts),
        ..healthy()
    });

    let check = report.check("broker.dumpable").unwrap();
    assert_eq!(check.state, CheckState::Warn);
    assert!(
        check.remedy.as_ref().unwrap().contains("debugger"),
        "the remedy should name what is wrong: {:?}",
        check.remedy
    );
    // Degraded, not blocked. A debuggable broker still works — it is just
    // observable to another same-uid process, which is the property this
    // product exists to reduce. An earlier version of this test asserted
    // `Ready` in the same breath as asserting a `Warn`, which is a
    // contradiction: a warn degrades by definition, and the assertion would
    // have failed the day someone read it.
    assert_eq!(report.status(), EnvelopeStatus::Degraded);
    assert!(
        report.blocking().is_empty(),
        "a debuggable broker is usable; it must not be reported as blocking: {:?}",
        report.blocking()
    );
}

// --- observing a real socket --------------------------------------------

/// UAT-DX-004's "broker incompatible", produced by a real broker-shaped peer
/// rather than by constructing the enum.
///
/// The peer is a real `UnixListener` answering a real `Ping` with a real
/// `Pong`, and the only thing wrong is the number inside it — which is exactly
/// the situation UAT-DX-004 describes, and exactly the one a test that built
/// `SocketOutcome::Answered` by hand would not have exercised.
#[test]
fn a_real_peer_answering_the_wrong_protocol_is_reported_as_incompatible() {
    use std::os::unix::net::{UnixListener, UnixStream};

    let dir = crate::tests_support::TempTree::new("wrong-protocol");
    let socket_path = dir.sub("broker.sock");
    let listener = UnixListener::bind(&socket_path).expect("bind a socket");

    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut request = [0u8; 4096];
            let _ = std::io::Read::read(&mut stream, &mut request);
            let wrong = asv_ipc_protocol::Response::Pong {
                protocol: asv_ipc_protocol::PROTOCOL_VERSION.wrapping_add(3),
            };
            let _ = stream.write_all(&serde_json::to_vec(&wrong).unwrap());
        }
    });

    let outcome = crate::observe_broker_socket_at(&socket_path);
    let _ = UnixStream::connect(&socket_path); // keep the listener alive until here

    assert!(
        matches!(outcome, SocketOutcome::Answered { .. }),
        "the peer answered and was not recognised: {outcome:?}"
    );

    let report = DoctorReport::judge(Observation {
        socket: outcome,
        ..healthy()
    });
    assert_eq!(report.blocking(), vec!["broker.protocol"]);
    assert_eq!(report.status(), EnvelopeStatus::Blocked);
}

/// The control for the test above: the same peer, the same socket, the right
/// protocol. Without it, "it reported `broker.protocol`" would also be what a
/// report that always blamed the protocol would say.
#[test]
fn a_real_peer_answering_the_right_protocol_is_accepted() {
    use std::os::unix::net::UnixListener;

    let dir = crate::tests_support::TempTree::new("right-protocol");
    let socket_path = dir.sub("broker.sock");
    let listener = UnixListener::bind(&socket_path).expect("bind a socket");

    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut request = [0u8; 4096];
            let _ = std::io::Read::read(&mut stream, &mut request);
            let right = asv_ipc_protocol::Response::Pong {
                protocol: asv_ipc_protocol::PROTOCOL_VERSION,
            };
            let _ = stream.write_all(&serde_json::to_vec(&right).unwrap());
        }
    });

    let outcome = crate::observe_broker_socket_at(&socket_path);

    assert_eq!(
        outcome,
        SocketOutcome::Answered {
            protocol: asv_ipc_protocol::PROTOCOL_VERSION
        }
    );
    let report = DoctorReport::judge(Observation {
        socket: outcome,
        ..healthy()
    });
    assert_eq!(report.status(), EnvelopeStatus::Ready);
    assert!(report.blocking().is_empty());
}

/// A socket nobody is listening on is `unreachable`, and that is the most
/// common state a user is in when they run `doctor` at all.
#[test]
fn a_socket_with_nothing_behind_it_is_unreachable_not_an_error() {
    let dir = crate::tests_support::TempTree::new("nobody-home");
    let socket_path = dir.sub("broker.sock");
    // Bound and dropped: the path exists in the filesystem sense and refuses
    // connections, which is the state a crashed broker leaves behind.
    {
        use std::os::unix::net::UnixListener;
        let _listener = UnixListener::bind(&socket_path).unwrap();
    }

    let outcome = crate::observe_broker_socket_at(&socket_path);
    assert!(
        matches!(outcome, SocketOutcome::Unreachable { .. }),
        "a dead socket reported as {outcome:?}"
    );
}

// --- R8: the unit points at this installation ---------------------------

/// A unit left behind by a previous install points somewhere else.
///
/// R8 in `11-RISKS-OPEN-QUESTIONS.md`, and the shape of it is a service that
/// starts happily: systemd does not care that the binary was replaced, it
/// runs the path it was given. So "the unit is installed" and "the unit is
/// right" are different facts and only one of them used to be checked.
#[test]
fn a_unit_pointing_at_another_installation_is_a_finding() {
    let report = DoctorReport::judge(Observation {
        // Installed by an older run, before the bundle moved.
        unit_target: Some("/home/u/.local/libexec/asv/asv-brokerd".into()),
        broker_lookup: BrokerLookup::Found(
            "/opt/mise/installs/agent-secretless/bin/../libexec/asv/asv-brokerd".into(),
        ),
        ..healthy()
    });

    assert_eq!(report.blocking(), vec!["install.unit_target"]);
    let check = report.check("install.unit_target").unwrap();
    assert!(check.detail.contains("mise"), "{}", check.detail);
    assert!(
        check.remedy.as_ref().unwrap().contains("asv setup"),
        "the remedy should be the command that fixes it: {:?}",
        check.remedy
    );
}

/// The control: same installation, same verdict. Without it, the test above
/// would also pass for a report that always failed this check.
#[test]
fn a_unit_pointing_at_this_installation_is_accepted() {
    let report = DoctorReport::judge(healthy());
    assert_eq!(
        report.check("install.unit_target").unwrap().state,
        CheckState::Ok
    );
    assert_eq!(report.status(), EnvelopeStatus::Ready);
}

/// A unit that still carries systemd's `%h` specifier is the state a layout
/// change leaves behind, and it is reported as the specifier rather than
/// quietly expanded — the point is that it is unresolved.
#[test]
fn a_unit_with_an_unexpanded_specifier_is_not_silently_accepted() {
    let dir = crate::tests_support::TempTree::new("specifier");
    let unit = dir.sub("asv-brokerd.service");
    std::fs::write(
        &unit,
        "ExecStart=%h/.local/libexec/asv/asv-brokerd %t/asv/broker.sock\n",
    )
    .unwrap();

    assert_eq!(
        unit_exec_start_binary(&unit),
        Some(PathBuf::from("%h/.local/libexec/asv/asv-brokerd")),
        "the specifier was resolved instead of being reported"
    );
}

/// The identity check, in the three states it is allowed to be in.
///
/// **Three, and not two, is the point.** "Not measured" and "measured and not
/// dedicated" are different facts with different remedies, and the diagnostic
/// that merged them is the reassuring one: a broker that cannot report its uid
/// would otherwise be read as a broker whose uid is fine. The M7 row spent a
/// milestone narrowing a claim precisely because that distinction had nowhere
/// to live, and this is where it lives now.
#[test]
fn the_identity_check_distinguishes_not_measured_from_not_dedicated() {
    let mut states = Vec::new();
    for identity in [
        None,
        Some(asv_ipc_protocol::BrokerIdentity::measured(1000, None)),
        Some(asv_ipc_protocol::BrokerIdentity::measured(998, Some(998))),
    ] {
        let report = DoctorReport::judge(Observation {
            socket: SocketOutcome::SelfReported(Box::new(crate::ipc::BrokerFacts {
                protocol: asv_ipc_protocol::PROTOCOL_VERSION,
                product_version: "0.26.0".into(),
                dumpable_disabled: true,
                no_new_privs: true,
                landlock_installed: true,
                seccomp_installed: true,
                capabilities: vec![],
                connect_listen: None,
                identity,
            })),
            broker_facts: None,
            ..healthy()
        });
        let check = report
            .check("broker.identity")
            .expect("the identity check must exist in every state");
        states.push((check.state, check.detail.clone(), check.remedy.clone()));
    }

    let (not_measured, shared, dedicated) = (&states[0], &states[1], &states[2]);

    // The three states are three *named* states, and the naming is the point:
    // `Unknown` because this build does not report an identity, `Info` because
    // a shared uid on an unpackaged deployment is what the product documents
    // rather than a fault in it, and `Ok` because there is nothing to advise.
    assert_eq!(
        not_measured.0,
        CheckState::Unknown,
        "a broker that reports no identity is not observable, not defective"
    );
    assert_eq!(
        shared.0,
        CheckState::Info,
        "a shared uid on an unpackaged deployment must not degrade the status: \
         a doctor that always reads Degraded is a doctor nobody reads"
    );

    // A broker that reported nothing is not a pass and not the same as shared.
    assert_ne!(
        not_measured.0, shared.0,
        "not measured and measured-and-shared must not be the same state"
    );
    assert_ne!(
        not_measured.1, shared.1,
        "the two states must not share a sentence, or the JSON would too"
    );
    assert_ne!(
        shared.0, dedicated.0,
        "a shared identity and a dedicated one are not the same verdict"
    );
    assert_eq!(
        dedicated.0,
        CheckState::Ok,
        "a dedicated identity is the one state that needs no remedy: {dedicated:?}"
    );
    assert!(
        dedicated.2.is_none(),
        "a check with nothing to advise must not invent advice: {dedicated:?}"
    );
    // And the remedy has to be actionable, because an operator cannot act on
    // "not dedicated" and can act on this.
    let remedy = shared.2.as_deref().unwrap_or_default();
    assert!(
        remedy.contains("--identity-uid") && remedy.contains("--require-dedicated-identity"),
        "the remedy must name both flags: {remedy:?}"
    );
}

/// The machine-readable half says the same three things, and says them by name.
///
/// Separate from the prose because this is the half a script reads, and a
/// script that cannot tell `not_measured` from `shared` will pick the
/// reassuring one.
#[test]
fn the_envelope_names_the_identity_state() {
    for (identity, expected) in [
        (None, "not_measured"),
        (
            Some(asv_ipc_protocol::BrokerIdentity::measured(1000, None)),
            "shared",
        ),
        (
            Some(asv_ipc_protocol::BrokerIdentity::measured(998, Some(998))),
            "dedicated",
        ),
    ] {
        let report = DoctorReport::judge(Observation {
            socket: SocketOutcome::SelfReported(Box::new(crate::ipc::BrokerFacts {
                protocol: asv_ipc_protocol::PROTOCOL_VERSION,
                product_version: "0.26.0".into(),
                dumpable_disabled: true,
                no_new_privs: true,
                landlock_installed: true,
                seccomp_installed: true,
                capabilities: vec![],
                connect_listen: None,
                identity,
            })),
            broker_facts: None,
            ..healthy()
        });
        let value: serde_json::Value =
            serde_json::from_str(&report.to_envelope().to_json()).unwrap();
        assert_eq!(
            value["data"]["identity"]["state"], expected,
            "wrong state in the envelope: {value}"
        );
        // A measured state carries the numbers; an unmeasured one carries no
        // `uid` at all, because reporting 0 there would read as root.
        if identity.is_none() {
            assert!(
                value["data"]["identity"].get("uid").is_none(),
                "an unmeasured identity must not report a uid: {value}"
            );
        } else {
            assert!(
                value["data"]["identity"]["uid"].is_number(),
                "a measured identity must carry the uid: {value}"
            );
        }
    }
}
