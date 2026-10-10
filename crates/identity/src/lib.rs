//! Workload identity derived from kernel evidence.
//!
//! ADR-0003 is the governing decision: "Self-declared agent names are metadata,
//! not authentication." Everything in this module exists to make that true in
//! code rather than in prose.
//!
//! The M0 implementation is deliberately narrow. It reads `SO_PEERCRED` from a
//! connected Unix socket, which is the one piece of evidence the kernel hands us
//! for free and cannot be spoofed by the peer. pidfd association and the rest
//! of the evidence ladder from `docs/08-IDENTITY-POLICY-CAPABILITIES.md` §1 are
//! M7 work; what matters in M0 is that the *type* carries only kernel-sourced
//! facts, so there is nowhere to put a lie.

use core::fmt;
use std::os::fd::OwnedFd;

/// Evidence about a connected peer, as reported by the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

impl fmt::Display for PeerCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pid={} uid={} gid={}", self.pid, self.uid, self.gid)
    }
}

/// Identity of the workload on the other end of a broker connection.
///
/// Fields are deliberately limited to kernel-attested facts. There is no
/// `agent_name: String` here, because a peer can put whatever it likes in
/// there. An agent profile name, if needed, belongs in the *session launch
/// record* the broker created, not in the connection.
///
/// `Clone`/`PartialEq` are intentionally absent: `OwnedFd` is neither, and a
/// pidfd is a unique kernel handle to one specific process, so copying it would
/// be semantically wrong even if the type allowed it.
#[derive(Debug)]
pub struct WorkloadIdentity {
    pub credentials: PeerCredentials,
    /// Stable process reference, once a pidfd has been opened. `None` until
    /// then; its absence must never be treated as "trusted anyway".
    pidfd: Option<OwnedFd>,
}

impl WorkloadIdentity {
    /// Builds an identity from kernel peer credentials, before pidfd
    /// association. This is a valid but weaker state.
    pub fn from_peer(credentials: PeerCredentials) -> Self {
        Self {
            credentials,
            pidfd: None,
        }
    }

    /// Whether the identity has been pinned to a live process.
    pub fn is_pidfd_pinned(&self) -> bool {
        self.pidfd.is_some()
    }

    /// Upgrades the identity by opening a `pidfd` for the peer PID.
    ///
    /// A pidfd removes the PID-reuse ambiguity described in ADR-0003: the
    /// descriptor refers to that specific process, so a later `/proc/<pid>`
    /// lookup or signal cannot be redirected to a recycled PID.
    ///
    /// Failure is reported, never ignored. A caller that cannot pin the
    /// process must decide explicitly whether its policy tolerates the weaker
    /// evidence.
    pub fn pin_pidfd(&mut self) -> Result<(), IdentityError> {
        if self.pidfd.is_some() {
            return Ok(());
        }
        // `nix` 0.29 does not expose pidfd_open, so this goes through libc
        // directly. The syscall takes (pid, flags) and returns a new fd, or
        // -1 with errno set. That is the whole contract.
        //
        // SAFETY: `pidfd_open` has no pointer arguments and no memory effects
        // beyond returning a descriptor, so there is nothing to make invalid.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, self.credentials.pid, 0u32) };
        if raw < 0 {
            return Err(IdentityError::PidfdOpen {
                pid: self.credentials.pid,
                source: std::io::Error::last_os_error(),
            });
        }
        // SAFETY: a non-negative return from pidfd_open is a fresh, owned fd.
        // There is no aliasing: this process has not seen this descriptor before.
        let fd = unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(raw as i32) };
        self.pidfd = Some(fd);
        Ok(())
    }

    /// Consumes the identity and returns the pinned pidfd, if any.
    ///
    /// Taking ownership transfers the kernel handle to the caller that needs to
    /// keep the process pinned (for example, a long-lived session record).
    pub fn into_pidfd(self) -> Option<OwnedFd> {
        self.pidfd
    }

    /// Reads the peer's executable path from procfs.
    ///
    /// This is *evidence*, not authentication: the file can be replaced by
    /// anything the same user can write. It exists so policy can reason about
    /// workload identity the way SPIRE does, and a caller that needs stronger
    /// assurance must combine it with a digest (M7).
    pub fn peer_executable(&self) -> Result<std::path::PathBuf, IdentityError> {
        let path = std::path::PathBuf::from(format!("/proc/{}/exe", self.credentials.pid));
        std::fs::read_link(&path).map_err(|source| IdentityError::ProcRead {
            pid: self.credentials.pid,
            path: path.clone(),
            source,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("pidfd_open failed for pid {pid}: {source}")]
    PidfdOpen {
        pid: i32,
        #[source]
        source: std::io::Error,
    },

    #[error("cannot read {path} for pid {pid}: {source}")]
    ProcRead {
        pid: i32,
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Reads kernel peer credentials from a connected Unix socket.
///
/// Returns `None` when the platform does not support `SO_PEERCRED`, which is
/// the honest outcome on a non-Linux target: the caller must then fail closed
/// rather than assume an identity.
#[cfg(target_os = "linux")]
pub fn peer_credentials(
    socket: &std::os::fd::BorrowedFd<'_>,
) -> Result<PeerCredentials, IdentityError> {
    use std::os::fd::AsRawFd;

    // SAFETY: `libc::ucred` is a POD struct of three `c_int` fields. Zeroing
    // a stack allocation of POD is well-defined and gives a known initial
    // state for the getsockopt out-parameter below.
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

    // SAFETY: `cred` and `len` are valid, correctly sized out-parameters for
    // getsockopt, and `socket` is a live borrowed descriptor for the call.
    let rc = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(cred).cast(),
            &mut len,
        )
    };

    if rc != 0 {
        return Err(IdentityError::ProcRead {
            pid: -1,
            path: std::path::PathBuf::from("SO_PEERCRED"),
            source: std::io::Error::last_os_error(),
        });
    }

    Ok(PeerCredentials {
        pid: cred.pid,
        uid: cred.uid,
        gid: cred.gid,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn peer_credentials(
    _socket: &std::os::fd::BorrowedFd<'_>,
) -> Result<PeerCredentials, IdentityError> {
    Err(IdentityError::ProcRead {
        pid: -1,
        path: std::path::PathBuf::from("SO_PEERCRED"),
        source: std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "SO_PEERCRED is Linux-only; this platform has no kernel peer evidence",
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;
    use std::os::unix::net::{UnixListener, UnixStream};

    const CANARY: &str = "ASV-CANARY-1e7d3a9f-DO-NOT-LEAK";

    /// M0 Exit: "broker and CLI communicate using kernel peer credentials".
    ///
    /// A real socketpair, real kernel credentials, real pidfd. Nothing mocked,
    /// because the whole point of ADR-0003 is that the evidence comes from the
    /// kernel and cannot be asserted by the test.
    #[test]
    fn peer_credentials_come_from_the_kernel() {
        let listener = UnixListener::bind("/tmp/asv-identity-test.sock").expect("bind");
        let client = UnixStream::connect("/tmp/asv-identity-test.sock").expect("connect");
        let (server, _addr) = listener.accept().expect("accept");

        let creds = peer_credentials(&server.as_fd()).expect("SO_PEERCRED must work on Linux");

        assert_eq!(creds.pid, std::process::id() as i32, "peer is this process");
        assert_eq!(creds.uid, unsafe { libc::getuid() });
        assert_eq!(creds.gid, unsafe { libc::getgid() });

        std::fs::remove_file("/tmp/asv-identity-test.sock").ok();
        drop(client);
    }

    /// A client cannot forge its uid: the kernel supplies it, not the peer.
    /// This is the property that makes the whole design work, so it is asserted
    /// against a real connection rather than a fabricated struct.
    #[test]
    fn peer_cannot_forge_its_own_identity() {
        let path = std::env::temp_dir().join(format!("asv-forge-{}.sock", std::process::id()));
        let listener = UnixListener::bind(&path).expect("bind");
        let client = UnixStream::connect(&path).expect("connect");
        let (server, _addr) = listener.accept().expect("accept");

        // The client "claims" to be root in the only way a peer can: by
        // sending bytes. The broker never reads those bytes to decide identity.
        use std::io::Write;
        let mut client = client;
        let _ = client.write_all(br#"{"pid":1,"uid":0,"gid":0}"#);

        let creds = peer_credentials(&server.as_fd()).expect("creds");
        assert_ne!(creds.uid, 0, "kernel uid must win over peer-supplied bytes");
        assert_eq!(creds.uid, unsafe { libc::getuid() });

        std::fs::remove_file(&path).ok();
    }

    /// pidfd association must actually pin a live process.
    #[test]
    fn pidfd_pinning_succeeds_for_a_live_process() {
        let mut identity = WorkloadIdentity::from_peer(PeerCredentials {
            pid: std::process::id() as i32,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        });
        assert!(!identity.is_pidfd_pinned());
        identity.pin_pidfd().expect("pidfd_open on self");
        assert!(identity.is_pidfd_pinned());
        // Idempotent: a second call must not replace a live pin.
        identity.pin_pidfd().expect("second pin is a no-op");
    }

    /// A PID that cannot exist must produce an error, never a silent
    /// "unpinned but trusted" state.
    #[test]
    fn pidfd_open_failure_is_reported() {
        let mut identity = WorkloadIdentity::from_peer(PeerCredentials {
            pid: i32::MAX,
            uid: 0,
            gid: 0,
        });
        let err = identity.pin_pidfd().expect_err("bogus pid must fail");
        assert!(matches!(err, IdentityError::PidfdOpen { pid, .. } if pid == i32::MAX));
        assert!(!identity.is_pidfd_pinned());
    }

    /// The identity type has no field a peer could populate with a lie, and
    /// certainly no secret-bearing field.
    #[test]
    fn identity_debug_never_carries_material() {
        let identity = WorkloadIdentity::from_peer(PeerCredentials {
            pid: 4242,
            uid: 1000,
            gid: 1000,
        });
        let rendered = format!("{identity:?}");
        assert!(rendered.contains("4242"));
        assert!(!rendered.contains(CANARY));
        assert!(!rendered.to_lowercase().contains("secret"));
    }
}
