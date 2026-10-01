//! Hostile tests for ADR-0015's control-plane admission rule.
//!
//! The rule exists to stop one specific mistake: concluding that a caller is
//! the human because it holds no known session. Each test below is built
//! around the way that mistake, or one like it, would slip through.

use asv_broker::admission::{
    admit_control_plane, parse_cgroup_membership, session_slice_path, sha256, ContentDigest,
    Denial, Enrolment, EvidenceError, ProcessEvidence, SESSION_SLICE_PREFIX,
};
use asv_broker::harden;
use asv_identity::WorkloadIdentity;
use std::path::{Path, PathBuf};

/// A process's evidence, scripted rather than read.
#[derive(Clone)]
struct Scripted {
    cgroups: Result<Vec<PathBuf>, EvidenceError>,
    executable: Result<(PathBuf, ContentDigest), EvidenceError>,
}

impl ProcessEvidence for Scripted {
    fn cgroups(&self, _pid: i32) -> Result<Vec<PathBuf>, EvidenceError> {
        self.cgroups.clone()
    }
    fn executable(&self, _pid: i32) -> Result<(PathBuf, ContentDigest), EvidenceError> {
        self.executable.clone()
    }
}

const DESKTOP: &str = "/opt/asv/bin/asv-desktop";
const DESKTOP_BYTES: &[u8] = b"#!/bin/sh\n# control plane\nexec true\n";

fn digest_of(bytes: &[u8]) -> ContentDigest {
    sha256(bytes)
}

fn enrolled_desktop() -> Enrolment {
    Enrolment::empty()
        .enrol(PathBuf::from(DESKTOP), digest_of(DESKTOP_BYTES))
        .enrol(PathBuf::from("/opt/asv/bin/asv-cli"), digest_of(b"cli"))
}

/// A peer that is pinned and outside any broker slice, running the desktop.
fn good_evidence() -> Scripted {
    Scripted {
        cgroups: Ok(vec![]),
        executable: Ok((PathBuf::from(DESKTOP), digest_of(DESKTOP_BYTES))),
    }
}

/// This process's pid, as `PeerCredentials` types it.
fn self_pid() -> i32 {
    i32::try_from(std::process::id()).expect("a pid that fits in i32")
}

/// A pinned peer. `WorkloadIdentity::from_peer` is unpinned, so a pinned one
/// has to be built the way `main.rs` builds it.
fn pinned_peer(pid: i32) -> WorkloadIdentity {
    let mut identity = WorkloadIdentity::from_peer(asv_identity::PeerCredentials {
        pid,
        uid: 1000,
        gid: 1000,
    });
    // `pin_pidfd` opens a pidfd for a *live* process, so the test uses this
    // process: pinning a pid that does not exist would fail for a reason that
    // has nothing to do with what is under test.
    identity.pin_pidfd().expect("pin this live process");
    identity
}

fn unpinned_peer(pid: i32) -> WorkloadIdentity {
    WorkloadIdentity::from_peer(asv_identity::PeerCredentials {
        pid,
        uid: 1000,
        gid: 1000,
    })
}

fn admit(
    peer: &WorkloadIdentity,
    enrolment: &Enrolment,
    evidence: &Scripted,
) -> Result<(), Denial> {
    admit_control_plane(peer, enrolment, evidence)
}

/// The rule admits a caller that satisfies all three conditions.
#[test]
fn a_pinned_enrolled_caller_outside_broker_control_is_admitted() {
    assert_eq!(
        admit(
            &pinned_peer(self_pid()),
            &enrolled_desktop(),
            &good_evidence()
        ),
        Ok(())
    );
}

/// Condition 3: no pin, no admission — even when everything else holds.
#[test]
fn an_unpinned_peer_is_refused_even_when_enrolled_and_outside_broker_control() {
    let err = admit(
        &unpinned_peer(self_pid()),
        &enrolled_desktop(),
        &good_evidence(),
    )
    .expect_err("an unpinned peer must not be admitted");
    assert_eq!(err, Denial::Unpinned);
    assert!(err.to_string().contains("pidfd-pinned"), "{err}");
}

/// Condition 1: a caller inside a slice this broker created is under broker
/// control, and no enrolment rescues it.
#[test]
fn a_caller_inside_a_broker_session_slice_is_refused() {
    let slice = session_slice_path(4242);
    let evidence = Scripted {
        cgroups: Ok(vec![slice.clone()]),
        executable: Ok((PathBuf::from(DESKTOP), digest_of(DESKTOP_BYTES))),
    };
    let err = admit(&pinned_peer(self_pid()), &enrolled_desktop(), &evidence)
        .expect_err("a caller under broker control must not be admitted");
    assert_eq!(err, Denial::UnderBrokerControl { slice });
    assert!(err.to_string().contains("under broker control"), "{err}");
}

/// Condition 2: the executable is not a principal the operator enrolled.
#[test]
fn a_caller_whose_executable_is_not_enrolled_is_refused() {
    let evidence = Scripted {
        cgroups: Ok(vec![]),
        executable: Ok((PathBuf::from("/tmp/other"), digest_of(b"other"))),
    };
    let err = admit(&pinned_peer(self_pid()), &enrolled_desktop(), &evidence)
        .expect_err("an unenrolled executable must not be admitted");
    assert_eq!(
        err,
        Denial::NotEnrolled {
            path: PathBuf::from("/tmp/other")
        }
    );
}

/// The same path with different contents is a different principal: a digest
/// binds the file, not the name.
#[test]
fn an_enrolled_path_with_different_contents_is_refused() {
    let evidence = Scripted {
        cgroups: Ok(vec![]),
        executable: Ok((PathBuf::from(DESKTOP), digest_of(b"tampered"))),
    };
    let err = admit(&pinned_peer(self_pid()), &enrolled_desktop(), &evidence)
        .expect_err("a substituted binary at an enrolled path must not be admitted");
    assert!(matches!(err, Denial::NotEnrolled { .. }), "{err}");
}

/// The empty record that every broker on this machine actually has. Nothing is
/// enrolled, so nothing is admitted — which is why wiring this rule to the
/// three control-plane verbs opens no door today.
#[test]
fn an_empty_enrolment_record_admits_nobody() {
    let err = admit(
        &pinned_peer(self_pid()),
        &Enrolment::empty(),
        &good_evidence(),
    )
    .expect_err("an empty record must admit nobody");
    assert!(matches!(err, Denial::NotEnrolled { .. }), "{err}");
    assert!(Enrolment::empty().principals().is_empty());
}

/// Condition 1 must be *observed*. An unreadable cgroup file is a denial, not
/// a pass: "we could not check" must never read as "there was nothing to
/// check", which is the absence trap wearing a different hat.
#[test]
fn an_unreadable_cgroup_file_is_a_denial_not_a_pass() {
    let evidence = Scripted {
        cgroups: Err(EvidenceError {
            what: "/proc/<pid>/cgroup",
            reason: "permission denied".into(),
        }),
        executable: Ok((PathBuf::from(DESKTOP), digest_of(DESKTOP_BYTES))),
    };
    let err = admit(&pinned_peer(self_pid()), &enrolled_desktop(), &evidence)
        .expect_err("unreadable evidence must deny");
    assert!(
        matches!(
            &err,
            Denial::EvidenceUnavailable {
                what: "/proc/<pid>/cgroup",
                ..
            }
        ),
        "{err}"
    );
    assert!(err.to_string().contains("never a pass"), "{err}");
}

/// Same for the executable: an unresolvable one denies.
#[test]
fn an_unreadable_executable_is_a_denial_not_a_pass() {
    let evidence = Scripted {
        cgroups: Ok(vec![]),
        executable: Err(EvidenceError {
            what: "/proc/<pid>/exe",
            reason: "no such file".into(),
        }),
    };
    let err = admit(&pinned_peer(self_pid()), &enrolled_desktop(), &evidence)
        .expect_err("an unresolvable executable must deny");
    assert!(
        matches!(
            &err,
            Denial::EvidenceUnavailable {
                what: "/proc/<pid>/exe",
                ..
            }
        ),
        "{err}"
    );
}

/// Every denial is distinct, so an operator can tell a misconfiguration from
/// an attack from a host that cannot answer.
#[test]
fn the_three_denials_are_distinguishable() {
    let unpinned = admit(&unpinned_peer(1), &enrolled_desktop(), &good_evidence());
    let controlled = admit(
        &pinned_peer(self_pid()),
        &enrolled_desktop(),
        &Scripted {
            cgroups: Ok(vec![session_slice_path(1)]),
            executable: Ok((PathBuf::from(DESKTOP), digest_of(DESKTOP_BYTES))),
        },
    );
    let unenrolled = admit(
        &pinned_peer(self_pid()),
        &enrolled_desktop(),
        &Scripted {
            cgroups: Ok(vec![]),
            executable: Ok((PathBuf::from("/x"), digest_of(b"x"))),
        },
    );
    let all = [unpinned, controlled, unenrolled];
    for i in 0..all.len() {
        for j in (i + 1)..all.len() {
            assert_ne!(all[i], all[j], "denials {i} and {j} must differ");
        }
    }
}

/// The parsing the condition rests on: a broker slice is detected, and an
/// ordinary slice is not mistaken for one.
#[test]
fn cgroup_parsing_finds_broker_slices_and_ignores_ordinary_ones() {
    let text = format!("0::/user.slice/user-1000.slice\n0::{SESSION_SLICE_PREFIX}4321\n");
    let found = parse_cgroup_membership(&text, "/sys/fs/cgroup");
    assert_eq!(found, vec![session_slice_path(4321)]);

    // A process in no broker slice parses to nothing, and that is the answer
    // for every caller that is genuinely outside broker control.
    let ordinary = "0::/user.slice/user-1000.slice\n0::/init.scope\n";
    assert!(parse_cgroup_membership(ordinary, "/sys/fs/cgroup").is_empty());
}

/// The slice name admission expects must be the one `harden.rs` builds. If
/// the naming changes, this is the assertion that says so instead of the
/// condition quietly passing everything.
#[test]
fn cgroup_slice_name_matches_the_convention() {
    assert_eq!(
        session_slice_path(7),
        Path::new("/sys/fs/cgroup").join(format!("{SESSION_SLICE_PREFIX}7"))
    );
    assert!(
        harden::session_slice_path(std::path::Path::new("/sys/fs/cgroup"), 7)
            .ends_with("asv.session.7")
    );
}
